"""Fraud-scoring neural network and its IBM ART adapter.

Design choice (explainable trade-off): the reference model is a small multilayer
perceptron written in NumPy with exact backpropagation, so the whole platform runs
on any CPU laptop without a multi-gigabyte deep-learning install. It is exposed to
IBM ART through `ARTFraudClassifier`, a genuine ART estimator, so ART's own FGSM,
PGD and AdversarialTrainer run against it unchanged. For a PyTorch model, swap the
adapter for `art.estimators.classification.PyTorchClassifier`; nothing else changes.
"""
from __future__ import annotations

import warnings

import numpy as np

warnings.filterwarnings("ignore", message=".*PyTorch not found.*")
from art.estimators.classification.classifier import ClassifierMixin  # noqa: E402
from art.estimators.estimator import BaseEstimator, LossGradientsMixin  # noqa: E402


class FraudMLP:
    """8 -> 32 -> 16 -> 2 network, ReLU hidden layers, softmax output, Adam optimiser."""

    def __init__(self, n_in: int = 8, hidden=(32, 16), seed: int = 0, lr: float = 3e-3,
                 fraud_weight: float = 3.0) -> None:
        rng = np.random.default_rng(seed)
        sizes = [n_in, *hidden, 2]
        self.W = [rng.normal(0, np.sqrt(2 / a), (a, b)) for a, b in zip(sizes[:-1], sizes[1:])]
        self.b = [np.zeros(b) for b in sizes[1:]]
        self.lr = lr
        self.class_w = np.array([1.0, fraud_weight])
        self._m = [np.zeros_like(p) for p in self.W + self.b]
        self._v = [np.zeros_like(p) for p in self.W + self.b]
        self._t = 0

    # ---------------------------------------------------------------- forward / backward
    def _forward(self, X):
        acts, pre = [X], []
        h = X
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            z = h @ W + b
            pre.append(z)
            h = np.maximum(z, 0) if i < len(self.W) - 1 else z
            acts.append(h)
        logits = acts[-1]
        e = np.exp(logits - logits.max(1, keepdims=True))
        return e / e.sum(1, keepdims=True), acts, pre

    def predict_proba(self, X):
        return self._forward(np.asarray(X, float))[0]

    def _backward(self, X, y_onehot):
        """Gradients of mean weighted cross-entropy w.r.t. parameters and inputs."""
        p, acts, pre = self._forward(X)
        w = (y_onehot * self.class_w).sum(1, keepdims=True)
        delta = w * (p - y_onehot) / len(X)
        gW, gb = [], []
        for i in reversed(range(len(self.W))):
            gW.insert(0, acts[i].T @ delta)
            gb.insert(0, delta.sum(0))
            delta = delta @ self.W[i].T
            if i > 0:
                delta = delta * (pre[i - 1] > 0)
        return gW, gb, delta * len(X)   # input gradient per sample (not averaged)

    def loss(self, X, y_onehot):
        p = self.predict_proba(X)
        w = (y_onehot * self.class_w).sum(1)
        return float(np.mean(-w * np.log((p * y_onehot).sum(1) + 1e-12)))

    def input_gradient(self, X, y_onehot):
        return self._backward(np.asarray(X, float), y_onehot)[2]

    def step(self, X, y_onehot):
        gW, gb, _ = self._backward(X, y_onehot)
        self._t += 1
        params, grads = self.W + self.b, gW + gb
        for i, (p, g) in enumerate(zip(params, grads)):
            self._m[i] = 0.9 * self._m[i] + 0.1 * g
            self._v[i] = 0.999 * self._v[i] + 0.001 * g * g
            mh = self._m[i] / (1 - 0.9 ** self._t)
            vh = self._v[i] / (1 - 0.999 ** self._t)
            p -= self.lr * mh / (np.sqrt(vh) + 1e-8)

    def fit(self, X, y, epochs: int = 15, batch: int = 128, seed: int = 0):
        rng = np.random.default_rng(seed)
        Y = np.eye(2)[y]
        for _ in range(epochs):
            idx = rng.permutation(len(X))
            for s in range(0, len(X), batch):
                j = idx[s:s + batch]
                self.step(X[j], Y[j])
        return self

    # ---------------------------------------------------------------- persistence
    def to_bytes(self) -> bytes:
        import io
        buf = io.BytesIO()
        np.savez(buf, *self.W, *self.b, class_w=self.class_w)
        return buf.getvalue()

    @classmethod
    def from_bytes(cls, data: bytes) -> "FraudMLP":
        import io
        d = np.load(io.BytesIO(data))
        arrs = [d[f"arr_{i}"] for i in range(len(d.files) - 1)]
        n = len(arrs) // 2
        m = cls.__new__(cls)
        m.W, m.b, m.class_w = arrs[:n], arrs[n:], d["class_w"]
        m.lr, m._t = 3e-3, 0
        m._m = [np.zeros_like(p) for p in m.W + m.b]
        m._v = [np.zeros_like(p) for p in m.W + m.b]
        return m


class ARTFraudClassifier(ClassifierMixin, LossGradientsMixin, BaseEstimator):
    """IBM ART estimator wrapping FraudMLP (enables ART attacks and defences)."""

    estimator_params = BaseEstimator.estimator_params + ClassifierMixin.estimator_params

    def __init__(self, model: FraudMLP, clip_values=(0.0, 1.0)) -> None:
        super().__init__(model=model, clip_values=clip_values)
        self.nb_classes = 2
        self._input_shape = (model.W[0].shape[0],)

    @property
    def input_shape(self):
        return self._input_shape

    def predict(self, x, batch_size: int = 1024, **kwargs):
        return self.model.predict_proba(x)

    def fit(self, x, y, batch_size: int = 128, nb_epochs: int = 1, **kwargs):
        y_idx = np.argmax(y, axis=1) if y.ndim == 2 else y
        self.model.fit(np.asarray(x, float), y_idx.astype(int), epochs=nb_epochs, batch=batch_size)

    def loss_gradient(self, x, y, **kwargs):
        y1 = y if y.ndim == 2 else np.eye(2)[y]
        return self.model.input_gradient(x, y1.astype(float)).astype(np.float32)

    def compute_loss(self, x, y, **kwargs):
        y1 = y if y.ndim == 2 else np.eye(2)[y]
        return self.model.loss(x, y1)

    def get_activations(self, *args, **kwargs):
        raise NotImplementedError

    def save(self, filename: str, path=None):
        raise NotImplementedError("use the Amanah model registry to persist models")
