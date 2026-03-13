from django.urls import path, include
from .views import (
    BalanceListView,
    BalanceSettleView,
    ExpenseUpdateView,
    MoneyGivenCreateView,
    MoneyGivenDetailView,
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
    path(
        "split-bill/",
        include(
            [
                path("", SplitBillCreateView.as_view(), name="split-bill-list"),
                path(
                    "<int:pk>/",
                    include(
                        [
                            path(
                                "",
                                SplitBillDetailView.as_view(),
                                name="split-bill-detail",
                            ),
                            path(
                                "add-member/",
                                AddMemberView.as_view(),
                                name="add-member",
                            ),
                            path(
                                "remove-member/",
                                RemoveMemberView.as_view(),
                                name="remove-member",
                            ),
                        ]
                    ),
                ),
            ]
        ),
    ),
    path(
        "split-bill/<int:split_bill_id>/",
        include(
            [
                path(
                    "members/<int:pk>/update/",
                    UpdateSplitBillMemberView.as_view(),
                    name="splitbill-member-update",
                ),
                path("balances/", BalanceListView.as_view(), name="balance-list"),
                path(
                    "balances/<int:balance_id>/settle/",
                    BalanceSettleView.as_view(),
                    name="balance-settle",
                ),
            ]
        ),
    ),
    path(
        "expenses/",
        include(
            [
                path("", ExpenseListView.as_view(), name="expense-list"),
                path("equal/", EqualExpenseCreateView.as_view(), name="expense-equal"),
                path(
                    "percentage/",
                    PercentageExpenseCreateView.as_view(),
                    name="expense-percentage",
                ),
                path(
                    "custom/", CustomExpenseCreateView.as_view(), name="expense-custom"
                ),
                path(
                    "<int:pk>/",
                    include(
                        [
                            path(
                                "", ExpenseDetailView.as_view(), name="expense-detail"
                            ),
                            path(
                                "update/",
                                ExpenseUpdateView.as_view(),
                                name="expense-update",
                            ),
                        ]
                    ),
                ),
            ]
        ),
    ),
    path(
        "money-given/",
        include(
            [
                path("", MoneyGivenCreateView.as_view(), name="money-given"),
                path(
                    "<int:pk>/",
                    MoneyGivenDetailView.as_view(),
                    name="money-given-detail",
                ),
            ]
        ),
    ),
    path("comments/", CommentCreateView.as_view(), name="comment-create"),
]
