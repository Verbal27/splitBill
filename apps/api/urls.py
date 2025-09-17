from django.urls import path, include
from .views import (
    ExpenseUpdateView,
    UpdateSplitBillMemberView,
    UserRegister,
    ResetPassword,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    UpdateUserView,
    SplitBillCreateView,
    SplitBillDetailView,
    CommentCreateView,
    AddMemberView,
    RemoveMemberView,
    ExpenseListView,
    EqualExpenseCreateView,
    PercentageExpenseCreateView,
    CustomExpenseCreateView,
    ExpenseDetailView,
    UserActivation,
    UserView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.routers import DefaultRouter


router = DefaultRouter()

urlpatterns = [
    path("", include(router.urls)),
    path("users/", UserView.as_view(), name="users"),
    path("users/<int:pk>/", UpdateUserView.as_view(), name="user-update"),
    path("register/", UserRegister.as_view(), name="register"),
    path("activate/<uidb64>/<token>/", UserActivation.as_view(), name="activate-user"),
    path("token/", TokenObtainPairView.as_view(), name="token-obtain-pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("reset-password/", ResetPassword.as_view(), name="password-reset"),
    path(
        "reset-password-confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(),
        name="reset-password-confirm",
    ),
    path(
        "reset-password-complete/",
        PasswordResetCompleteView.as_view(),
        name="password-reset-complete",
    ),
    path("split-bill/", SplitBillCreateView.as_view(), name="split-bill-list"),
    path(
        "split-bill/<int:pk>/", SplitBillDetailView.as_view(), name="split-bill-detail"
    ),
    path("split-bill/<int:pk>/add-member/", AddMemberView.as_view(), name="add-member"),
    path(
        "split-bill/<int:pk>/remove-member/",
        RemoveMemberView.as_view(),
        name="remove-member",
    ),
    path(
        "split-bill/<int:split_bill_id>/members/<int:pk>/update/",
        UpdateSplitBillMemberView.as_view(),
        name="splitbill-member-update",
    ),
    path("expenses/", ExpenseListView.as_view(), name="expense-list"),
    path("expenses/equal", EqualExpenseCreateView.as_view(), name="expense-equal"),
    path(
        "expenses/percentage",
        PercentageExpenseCreateView.as_view(),
        name="expense-percentage",
    ),
    path("expenses/custom", CustomExpenseCreateView.as_view(), name="expense-custom"),
    path("expenses/<int:pk>/", ExpenseDetailView.as_view(), name="expense-detail"),
    path(
        "expenses/<int:pk>/update", ExpenseUpdateView.as_view(), name="expense-detail"
    ),
    path("comments/", CommentCreateView.as_view(), name="comment-create"),
]
