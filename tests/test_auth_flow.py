from fastapi.testclient import TestClient
from app.main import app
import uuid

client = TestClient(app)

def test_register_and_login():
    # Generate unique email
    email = f"test_{uuid.uuid4()}@example.com"
    password = "securepassword123"
    
    # 1. Register
    print(f"Testing registration for {email}...")
    response = client.post(
        "/auth/register",
        json={
            "email": email, 
            "password": password, 
            "confirm_password": password,
            "full_name": "Test User"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert "id" in data
    print("Registration successful!")
    
    # 2. Login
    print("Testing login...")
    response = client.post(
        "/auth/login",
        data={"username": email, "password": password}
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    token = token_data["access_token"]
    print("Login successful, got token!")
    
    # 3. Access Protected Route
    print("Testing protected route...")
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    user_data = response.json()
    assert user_data["email"] == email
    print("Protected route access successful!")

if __name__ == "__main__":
    try:
        test_register_and_login()
        print("\nAll tests passed!")
    except Exception as e:
        print(f"\nTest failed: {e}")
        raise e
