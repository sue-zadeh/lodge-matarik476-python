"""Render rate-limit feedback without running a rejected form submission."""

from math import ceil
import time

from flask import make_response, render_template, request


def register_error_pages(app, limiter):
    @app.errorhandler(429)
    def handle_rate_limit(_error):
        request_limit = limiter.current_limit
        retry_seconds = (
            max(1, ceil(request_limit.reset_at - time.time()))
            if request_limit else None
        )
        templates = {
            "forgot_password": "forgot_password.html",
            "reset_password": "reset_password.html",
            "register": "register.html",
            "login": "login.html",
            "contact": "contact.html",
        }
        next_steps = {
            "forgot_password": (
                "Check your inbox and spam folder. You can still use the latest "
                "reset email if its link has not expired. A new request has not been sent."
            ),
            "reset_password": (
                "Your password has not been changed by this attempt. After waiting, "
                "try this link again. If it has expired, request a new reset link."
            ),
            "register": "This attempt has not created an account. Please try again after waiting.",
            "login": "Please wait before trying to sign in again.",
            "contact": "This attempt has not sent your message. Please try again after waiting.",
        }
        response = make_response(
            render_template(
                templates.get(request.endpoint, "errors/429.html"),
                rate_limited=True,
                retry_after_seconds=retry_seconds,
                retry_after_minutes=ceil(retry_seconds / 60) if retry_seconds else None,
                rate_limit_help=next_steps.get(
                    request.endpoint, "Please wait before trying this action again."
                ),
                # Never copy submitted passwords or other personal data into an error page.
                form={},
                errors={},
            ),
            429,
        )
        response.headers["Cache-Control"] = "no-store"
        if retry_seconds is not None:
            response.headers["Retry-After"] = str(retry_seconds)
        return response
