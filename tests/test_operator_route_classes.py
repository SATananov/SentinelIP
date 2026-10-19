from fastapi.middleware.cors import CORSMiddleware

import api.main as api_main
from api.remote_sensors import local_management
from test_operator_analyst_boundary import (
    ANALYST_ROUTES,
    REVIEW_ROUTES,
    SENSOR_ROUTES,
    _has_local_guard,
    _route_map,
)
from test_operator_control_plane_boundary import PROTECTED_ROUTE_METHODS


LOCAL_OPERATOR_CONTROL = PROTECTED_ROUTE_METHODS
LOCAL_OPERATOR_ANALYST = REVIEW_ROUTES | ANALYST_ROUTES
SENSOR_AUTHENTICATED = SENSOR_ROUTES
LIMITED_PUBLIC_READ = {("GET", "/health")}


def test_final_operator_route_classes_have_expected_local_boundary():
    routes = _route_map()
    assert LOCAL_OPERATOR_CONTROL <= routes.keys()
    assert LOCAL_OPERATOR_ANALYST <= routes.keys()
    assert SENSOR_AUTHENTICATED <= routes.keys()
    assert LIMITED_PUBLIC_READ <= routes.keys()

    assert all(_has_local_guard(routes[key])
               for key in LOCAL_OPERATOR_CONTROL | LOCAL_OPERATOR_ANALYST)
    assert all(not _has_local_guard(routes[key])
               for key in SENSOR_AUTHENTICATED | LIMITED_PUBLIC_READ)


def test_limited_public_health_payload_remains_minimal():
    assert api_main.health() == {"status": "ok", "service": "SentinelIP"}


def test_cors_keeps_only_local_frontend_origins_and_supports_operator_put():
    cors = next(middleware for middleware in api_main.app.user_middleware
                if middleware.cls is CORSMiddleware)
    assert set(cors.kwargs["allow_origins"]) == {
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
    assert cors.kwargs["allow_methods"] == ["GET", "POST", "PATCH", "PUT", "DELETE"]

