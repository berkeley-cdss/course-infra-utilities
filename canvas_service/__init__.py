from flask import session, request, url_for, current_app
from canvasapi import Canvas
from canvasapi.user import User
from canvasapi.course import Course
from canvasapi.account import Account
from canvasapi.paginated_list import PaginatedList
import os
from dotenv import load_dotenv
from common.course_config import get_bcourses_id
import time
import requests

def _get_client(key=None) -> Canvas:
    if not key:
        #refresh access token if expired
        refresh_access_token()
        key = session.get('access_token', None)
    if not key:
        raise Exception('Key and access token not found')
    load_dotenv(override=True)
    return Canvas(os.getenv('CANVAS_SERVER_URL'), key)

def get_student_from_email(email, key=None):
    course_id = get_bcourses_id()
    course = get_course(course_id, key)
    students = course.get_enrollments(type=['StudentEnrollment'])
    for enrollment in students:
        student = enrollment.user
        if email == student["login_id"]:
            return student["name"]
    return None # no student found

def get_user(user_id, key=None) -> User:
    return _get_client(key).get_user(user_id)

def get_course(course_id, key=None) -> Course:
    return _get_client(key).get_course(course_id)

def get_users(account_id, search_term, key=None) -> PaginatedList:
    return _get_client(key).get_account(account_id).get_users(search_term)

def get_email(user_id, key=None) -> str | None:
    return get_user(user_id, key).get_profile().get('primary_email')

def get_name(user_id, key=None) -> str | None:
    return get_user(user_id, key).get_profile().get('name')

def get_preferred_name(user_id, key=None) -> str | None:
    return get_user(user_id, key).get_profile().get('short_name')

def get_user_courses(user_id, key=None) -> list[Course]:
    return [c for c in get_user(user_id, key).get_courses(enrollment_status='active', include=['term'], per_page=100)]

def is_staff(course, user_id, key=None):
    """ Returns whether a user is a TA or Teacher of the given course.

    Args:
        course (Course): CanvasAPI course object
        user_id (str | int): Canvas id for the user

    Returns:
        bool: True if user has staff role in course.
    """
    for e in course.get_enrollments(user_id=str(user_id)):
        staff_types = ["TaEnrollment", "TeacherEnrollment"]
        if e.type in staff_types:
            return True
    if 1549197 in [c.id for c in get_user_courses(user_id, key)]:
        return True
    return False

def is_admin(course, user_id, key=None):
    """ Returns whether a user is a Teacher or Lead TA of the given course.

    Args:
        course (Course): CanvasAPI course object
        user_id (str | int): Canvas id for the user

    Returns:
        bool: True if user has admin role in course.
    """
    # admin privilege assigned if enrolled as a teacher or lead TA on bCourses
    for e in course.get_enrollments(user_id=str(user_id)):
        if e.type == "TeacherEnrollment" or e.role == "Lead TA":
            return True
    # admin privilege assigned if enrolled in bCourses project for override purposes
    # contact Silas to be added to this course
    if 1549197 in [c.id for c in get_user_courses(user_id, key)]:
        return True
    return False

def refresh_access_token():
    current_app.logger.info("Start refreshing our token")
    expiry = session.get("token_expires_at", 0)
    buffer = 60 #one minute buffer time
    if time.time() + buffer >= expiry:
        refresh_token = session.get("refresh_token", None)
        if not refresh_token:
            raise Exception('Refresh token not found')
        token_url = current_app.config.get("CANVAS_TOKEN_URL")
        client_id = current_app.config.get("CANVAS_CLIENT_ID")
        client_secret = current_app.config.get("CANVAS_CLIENT_SECRET")

        if not token_url or not client_id or not client_secret:
            raise Exception("Canvas Oauth client configuration missing CANVAS_TOKEN_URL or CANVAS_CLIENT_ID or CANVAS_CLIENT_SECRET")
        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
        }

        try:
            r = requests.post(token_url, data=data, timeout=10)
        except requests.RequestException as e:
            raise Exception(f"Token refresh request failed: {e}") from e

        if r.status_code != 200:
            raise Exception(f"Token refresh failed with HTTP {r.status_code}: {r.text}")
        token_resp = r.json()
        new_access = token_resp.get("access_token")
        if not new_access:
            raise Exception("Token refresh missing access_token")
        session["access_token"] = new_access
        session["token_expires_at"] = time.time() + token_resp.get("expires_in", 3600)
        #logn/oauth2/token API shouldn't provide refresh token, but add as a safety check
        if token_resp.get("refresh_token"):
            session["refresh_token"] = token_resp["refresh_token"]
