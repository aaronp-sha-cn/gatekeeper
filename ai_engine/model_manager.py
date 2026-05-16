"""
GateKeeper - 模型管理器
管理AI模型的加载、保存、训练和版本控制

安全警告：pickle 模块存在反序列化安全风险。加载不受信任来源的 .pkl 文件
可能导致任意代码执行。本模块优先使用 joblib 进行模型序列化（更安全、更高效），
仅在 joblib 不可用时回退到 pickle。请勿加载来自不可信来源的模型文件。
"""

import os
import json
import pickle
import threading
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

try:
    import joblib
    HAS_JOBLIB = True
except ImportError:
    HAS_JOBLIB = False

try:
    import numpy as np
except ImportError:
    np = None

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import KMeans
except ImportError:
    IsolationForest = None
    StandardScaler = None
    KMeans = None

from config.settings import settings
from config.logging_config import get_logger

logger = get_logger("model_manager")


class ModelManager:
    """
    AI模型管理器
    负责模型的持久化存储、加载和版本管理
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._model_dir = Path(settings.ai_model.model_path)
        self._model_dir.mkdir(parents=True, exist_ok=True)

        # 模型注册表
        self._models: Dict[str, Any] = {}
        self._model_metadata: Dict[str, Dict] = {}

        # 模型文件路径映射
        self._model_files = {
            "isolation_forest": self._model_dir / "isolation_forest.pkl",
            "scaler": self._model_dir / "scaler.pkl",
            "kmeans": self._model_dir / "kmeans.pkl",
            "metadata": self._model_dir / "metadata.json",
        }

        logger.info("模型管理器初始化完成，模型目录: {}".format(self._model_dir))

    def load_models(self) -> Dict[str, bool]:
        """
        加载所有已保存的模型

        Returns:
            各模型加载状态
        """
        with self._lock:
            results = {}

            # 加载 Isolation Forest
            results["isolation_forest"] = self._load_model(
                "isolation_forest",
                IsolationForest(n_estimators=100, contamination=0.1, random_state=42),
            )

            # 加载 StandardScaler
            results["scaler"] = self._load_model(
                "scaler",
                StandardScaler(),
            )

            # 加载 KMeans
            results["kmeans"] = self._load_model(
                "kmeans",
                KMeans(n_clusters=5, random_state=42, n_init=10),
            )

            # 加载元数据
            self._load_metadata()

            loaded_count = sum(1 for v in results.values() if v)
            logger.info(
                "模型加载完成: {}/{} 个模型成功加载".format(loaded_count, len(results))
            )

            return results

    def _load_model(self, name: str, default_model: Any) -> bool:
        """
        加载单个模型

        Args:
            name: 模型名称
            default_model: 默认模型实例（加载失败时使用）

        Returns:
            是否成功加载已保存的模型
        """
        filepath = self._model_files.get(name)
        if not filepath:
            logger.warning("未知模型: {}".format(name))
            self._models[name] = default_model
            return False

        if not filepath.exists():
            logger.info("模型文件不存在，使用默认模型: {}".format(name))
            self._models[name] = default_model
            return False

        try:
            if HAS_JOBLIB:
                model = joblib.load(filepath)
            else:
                raise RuntimeError("joblib 库未安装，无法安全加载模型文件。请安装 joblib。")
            self._models[name] = model
            logger.info("模型加载成功: {}".format(name))
            return True
        except Exception as e:
            logger.error("模型加载失败: {}, 错误: {}".format(name, e))
            self._models[name] = default_model
            return False

    def save_models(self) -> Dict[str, bool]:
        """
        保存所有模型到磁盘

        优先使用 joblib 进行序列化，joblib 对 numpy 数组更高效且更安全。
        如果 joblib 不可用，回退到 pickle。

        Returns:
            各模型保存状态
        """
        return self.save_models_safe()

    def save_models_safe(self) -> Dict[str, bool]:
        """
        使用 joblib 安全保存所有模型（带 pickle 回退）

        优先使用 joblib 进行序列化，joblib 对 numpy 数组更高效且更安全。
        如果 joblib 不可用，回退到 pickle。

        Returns:
            各模型保存状态
        """
        with self._lock:
            results = {}

            for name, model in self._models.items():
                filepath = self._model_files.get(name)
                if filepath and model is not None:
                    try:
                        if HAS_JOBLIB:
                            joblib.dump(model, filepath)
                            logger.info("模型安全保存成功 (joblib): {}".format(name))
                        else:
                            with open(filepath, "wb") as f:
                                pickle.dump(model, f)
                            logger.info("模型安全保存成功 (pickle fallback): {}".format(name))
                        results[name] = True
                    except Exception as e:
                        results[name] = False
                        logger.error("模型安全保存失败: {}, 错误: {}".format(name, e))

            # 保存元数据
            self._save_metadata()

            return results

    def save_model(self, name: str, model: Any) -> bool:
        """
        保存单个模型

        优先使用 joblib 进行序列化，joblib 对 numpy 数组更高效且更安全。
        如果 joblib 不可用，回退到 pickle（已弃用，建议安装 joblib）。

        Args:
            name: 模型名称
            model: 模型实例

        Returns:
            是否保存成功
        """
        filepath = self._model_files.get(name)
        if not filepath:
            logger.error("未知模型: {}".format(name))
            return False

        try:
            self._models[name] = model
            if HAS_JOBLIB:
                joblib.dump(model, filepath)
                logger.info("模型保存成功 (joblib): {}".format(name))
            else:
                # 已弃用: pickle 存在反序列化安全风险，建议安装 joblib
                import warnings
                warnings.warn(
                    "使用 pickle 保存模型已弃用，存在安全风险。请安装 joblib: pip install joblib",
                    DeprecationWarning,
                    stacklevel=2,
                )
                with open(filepath, "wb") as f:
                    pickle.dump(model, f)
                logger.info("模型保存成功 (pickle fallback, 已弃用): {}".format(name))
            return True
        except Exception as e:
            logger.error("模型保存失败: {}, 错误: {}".format(name, e))
            return False

    def get_model(self, name: str) -> Optional[Any]:
        """
        获取模型实例

        Args:
            name: 模型名称

        Returns:
            模型实例或None
        """
        return self._models.get(name)

    def train_isolation_forest(
        self,
        X: np.ndarray,
        n_estimators: int = 100,
        contamination: float = 0.1,
    ) -> Dict[str, Any]:
        """
        训练 Isolation Forest 模型

        Args:
            X: 训练特征矩阵
            n_estimators: 树的数量
            contamination: 异常比例

        Returns:
            训练结果
        """
        logger.info(
            "开始训练 Isolation Forest: "
            "样本数={}, 树数={}".format(len(X), n_estimators)
        )

        # 标准化
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # 训练模型
        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        # 保存模型
        self.save_model("isolation_forest", model)
        self.save_model("scaler", scaler)

        # 更新元数据
        self._model_metadata["isolation_forest"] = {
            "trained_at": datetime.now().isoformat(),
            "n_samples": len(X),
            "n_features": X.shape[1],
            "n_estimators": n_estimators,
            "contamination": contamination,
        }

        # 计算训练指标
        scores = model.decision_function(X_scaled)
        metrics = {
            "mean_score": round(float(np.mean(scores)), 4),
            "std_score": round(float(np.std(scores)), 4),
            "min_score": round(float(np.min(scores)), 4),
            "max_score": round(float(np.max(scores)), 4),
        }

        logger.info("Isolation Forest 训练完成: {}".format(metrics))
        return {"status": "ok", "metrics": metrics}

    def train_kmeans(
        self,
        X: np.ndarray,
        n_clusters: int = 5,
    ) -> Dict[str, Any]:
        """
        训练 KMeans 聚类模型

        Args:
            X: 训练特征矩阵
            n_clusters: 聚类数量

        Returns:
            训练结果
        """
        logger.info(
            "开始训练 KMeans: 样本数={}, 聚类数={}".format(len(X), n_clusters)
        )

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        model.fit(X_scaled)

        self.save_model("kmeans", model)

        self._model_metadata["kmeans"] = {
            "trained_at": datetime.now().isoformat(),
            "n_samples": len(X),
            "n_features": X.shape[1],
            "n_clusters": n_clusters,
            "inertia": round(float(model.inertia_), 4),
        }

        logger.info("KMeans 训练完成: inertia={:.4f}".format(model.inertia_))
        return {"status": "ok", "inertia": round(float(model.inertia_), 4)}

    def _load_metadata(self):
        """加载模型元数据"""
        filepath = self._model_files["metadata"]
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    self._model_metadata = json.load(f)
            except Exception as e:
                logger.warning("加载模型元数据失败: {}".format(e))

    def _save_metadata(self):
        """保存模型元数据"""
        filepath = self._model_files["metadata"]
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self._model_metadata, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error("保存模型元数据失败: {}".format(e))

    def get_model_info(self) -> Dict[str, Any]:
        """获取所有模型的信息"""
        info = {
            "model_dir": str(self._model_dir),
            "loaded_models": list(self._models.keys()),
            "metadata": self._model_metadata,
        }

        for name in self._models:
            filepath = self._model_files.get(name)
            if filepath:
                info[name] = {
                    "file": str(filepath),
                    "exists": filepath.exists(),
                    "size_bytes": filepath.stat().st_size if filepath.exists() else 0,
                }

        return info

    def reset_models(self) -> Dict[str, bool]:
        """重置所有模型为默认值"""
        results = {}
        for name in list(self._models.keys()):
            filepath = self._model_files.get(name)
            if filepath and filepath.exists():
                try:
                    filepath.unlink()
                    results[name] = True
                except Exception as e:
                    results[name] = False
                    logger.error("删除模型文件失败: {}, {}".format(name, e))

        self._models.clear()
        self._model_metadata.clear()
        logger.info("所有模型已重置")
        return results
