from fastapi import FastAPI

from app.api.open_ports import router as open_ports_router
from app.api.targets import router as targets_router
from app.routers.decisions import router as decisions_router
from app.routers.llm_tools import router as llm_tools_router
from app.routers.approval import router as approval_router

app = FastAPI(title="M2A Pentest API", version="0.1.0")
app.include_router(targets_router)
app.include_router(open_ports_router)
app.include_router(decisions_router)
app.include_router(llm_tools_router)
app.include_router(approval_router)
