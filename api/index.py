from app.main import app
from mangum import Mangum

# Vercel serverless handler
handler = Mangum(app, lifespan="off")
