from django.urls import path
from . import views
urlpatterns = [path("", views.dashboard, name="dashboard"), path("login/", views.login_view, name="login"), path("logout/", views.logout_view, name="logout"), path("fir/new/", views.create_fir, name="create_fir"), path("fir/<str:fir_id>/", views.detail, name="detail"), path("fir/<str:fir_id>/verify/", views.verify, name="verify")]
