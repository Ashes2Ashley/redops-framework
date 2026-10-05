import importlib
import pkgutil
from typing import Dict, Type, List, Any
from core.base_module import BaseModule, ModuleResult

class ModuleEngine:
    def __init__(self, modules_package: str = "modules", scope=None,
                 audit=None, cache_dir=None, allow_all: bool = False):
        self.modules_package = modules_package
        self.scope = scope
        self.audit = audit
        self.cache_dir = cache_dir
        self.allow_all = allow_all
        self.registry: Dict[str, Type[BaseModule]] = {}
        self.discover_modules()

    def discover_modules(self) -> None:
        self.registry.clear()
        package = importlib.import_module(self.modules_package)
        for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            if not is_pkg:
                mod = importlib.import_module(module_name)
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        instance_stub = attr(target="")
                        self.registry[instance_stub.name] = attr

    def list_modules(self) -> List[Dict[str, str]]:
        output = []
        for name, cls in self.registry.items():
            stub = cls(target="")
            output.append({"name": stub.name, "description": stub.description})
        return output

    def execute_module(self, module_name: str, target: str, config: Dict[str, Any] = None) -> ModuleResult:
        if module_name not in self.registry:
            result = ModuleResult(module_name=module_name, target=target, status="FAILED")
            result.errors.append(f"Module '{module_name}' is not registered.")
            return result

        module_class = self.registry[module_name]
        config = dict(config or {})
        # Engine context: scope, audit, cache flow into every module.
        # Modules read these via self.http_client(); direct _keys are private.
        config.setdefault("_scope", self.scope)
        config.setdefault("_audit", self.audit)
        config.setdefault("_cache_dir", self.cache_dir)
        config.setdefault("_allow_all", self.allow_all)
        instance = module_class(target=target, config=config)
        try:
            return instance.run()
        except Exception as e:
            result = ModuleResult(module_name=module_name, target=target, status="EXCEPTION")
            result.errors.append(f"Unhandled exception during execution: {str(e)}")
            return result
