from fastapi import APIRouter, Depends, HTTPException
from config.auth import verify_token
from .schemas import ClientBase
from .services import (
    create_client_service,
    get_clients_service,
    update_client_service,
    delete_client_service
)

router = APIRouter(prefix="/clients", tags=["Clients"])


@router.post("/")
def create_client(client: ClientBase, current_user: dict = Depends(verify_token)):
    return create_client_service(client)


@router.get("/")
def get_clients(current_user: dict = Depends(verify_token)):
    return get_clients_service()


@router.put("/{client_id}")
def update_client(client_id: int, client: ClientBase, current_user: dict = Depends(verify_token)):
    return update_client_service(client_id, client)


@router.delete("/{client_id}")
def delete_client(client_id: int, current_user: dict = Depends(verify_token)):
    delete_client_service(client_id)
    return {"message": "Client deleted successfully", "client_id": client_id}