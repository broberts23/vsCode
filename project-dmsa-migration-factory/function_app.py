import azure.functions as func

from functions.inventory import bp as inventory_bp
from functions.migrate import bp as migrate_bp
from functions.rollback import bp as rollback_bp
from functions.validate import bp as validate_bp

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

app.register_functions(inventory_bp)
app.register_functions(migrate_bp)
app.register_functions(validate_bp)
app.register_functions(rollback_bp)
