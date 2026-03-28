from functools import wraps
from typing import Callable, List, Optional, Any

class SecployRegister:
    """
    Register functions and endpoints to be monitored and controlled by Secploy Gate.
    Usage:
        reg = SecployRegister(functions=[myfunc, ...], endpoints=[...], gate=secploy_gate)
        # or
        @reg.monitor
        def myfunc(...): ...
    """
    def __init__(self, functions: Optional[List[Callable]] = None, endpoints: Optional[List[str]] = None, gate: Any = None):
        self.gate = gate
        self.monitored_functions = []
        self.monitored_endpoints = endpoints or []
        if functions:
            for fn in functions:
                self.register_function(fn)

    def register_function(self, fn: Callable) -> Callable:
        """Wrap and register a function for monitoring."""
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Call the gate before function execution
            if self.gate:
                # Use function name as identifier
                self.gate(request={
                    'method': 'FUNCTION',
                    'endpoint': fn.__qualname__,
                    'metadata': {'type': 'function', 'args': args, 'kwargs': kwargs},
                })
            return fn(*args, **kwargs)
        self.monitored_functions.append(wrapper)
        return wrapper

    def monitor(self, fn: Callable) -> Callable:
        """Decorator to monitor a function."""
        return self.register_function(fn)

    def is_endpoint_monitored(self, endpoint: str) -> bool:
        return endpoint in self.monitored_endpoints

    def is_function_monitored(self, fn: Callable) -> bool:
        return any(f.__name__ == fn.__name__ for f in self.monitored_functions)
