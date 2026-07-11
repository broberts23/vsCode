import azure.functions as func

from functions.elevate import jit_elevate_access as jit_elevate_access_bp
from functions.poll_revoke import poll_and_revoke_trigger as poll_and_revoke_trigger_bp

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)
app.register_functions(poll_and_revoke_trigger_bp)
app.register_functions(jit_elevate_access_bp)
