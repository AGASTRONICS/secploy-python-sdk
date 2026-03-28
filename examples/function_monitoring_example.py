from secploy import SecployClient, SecployGate, SecployRegister

# Example usage
client = SecployClient()
gate = client.security_gate()

# Register a function for monitoring
reg = SecployRegister(functions=[], endpoints=["/api/critical"], gate=gate)

@reg.monitor
def protected_function(x, y):
    print(f"Running protected_function with {x}, {y}")
    return x + y

# Call the function (will be checked by the gate)
protected_function(1, 2)

# Register more functions dynamically

def another_func():
    print("Another monitored function")

reg.register_function(another_func)
another_func()

# Check endpoint monitoring
print(reg.is_endpoint_monitored("/api/critical"))  # True
print(reg.is_function_monitored(protected_function))  # True
