from pydantic import BaseModel, Field


class EmailScanRequest(BaseModel):
    sender: str = Field(min_length=3, max_length=320, description='e.g. "PayPal Support <support@paypal.com>"')
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1, max_length=20000)
