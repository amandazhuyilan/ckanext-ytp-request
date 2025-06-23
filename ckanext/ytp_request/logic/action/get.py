from ckan import logic, model
from ckan.common import config, session, _
from ckan.lib.dictization import model_dictize
from ckanext.ytp_request.model import MemberRequest
from ckanext.ytp_request.helper import get_organization_admins
from datetime import datetime
from sqlalchemy import desc
from sqlalchemy.sql.expression import or_
from ckan.plugins import toolkit

import logging
import ckan.authz as authz

log = logging.getLogger(__name__)

NotFound = logic.NotFound


def member_request(context, data_dict):
    logic.check_access('member_request_show', context, data_dict)
    mrequest_id = data_dict.get('mrequest_id', None)

    membership = model.Session.query(model.Member).get(mrequest_id)
    if not membership:
        raise logic.NotFound("Member request not found")

    # Return most current instance from memberrequest table
    member_request = model.Session.query(MemberRequest).filter(
        MemberRequest.membership_id == mrequest_id).order_by(MemberRequest.request_date.desc()).limit(1).first()
    if not member_request:
        raise logic.NotFound(
            "Member request associated with membership not found")

    member_dict = {}
    member_dict['id'] = mrequest_id
    member_dict['organization_name'] = membership.group.name
    member_dict['group_id'] = membership.group_id
    member_dict['role'] = member_request.role
    member_dict['state'] = member_request.status
    member_dict['message'] = member_request.message
    member_dict['request_date'] = member_request.request_date.strftime(
        "%d - %b - %Y")
    member_dict['user_id'] = membership.table_id
    return member_dict


def member_requests_mylist(context, data_dict):
    ''' Users will see a list of their member requests '''
    logic.check_access('member_requests_mylist', context, data_dict)

    user = context.get('user', None)

    user_object = model.User.get(user)

    # Collect standard CKAN membership requests
    membership_requests = model.Session.query(model.Member).filter(
        model.Member.table_id == user_object.id).all()
    results = _membership_request_list_dictize(membership_requests, context)

    def _format_iso_date(iso_ts):
        try:
            dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
            return dt.strftime("%d - %B - %Y")
        except Exception:
            return iso_ts[:10] if iso_ts else None

    pending_orgs = session.get("ckanext:oidc-pkce:pending_org_ids", [])
    existing_ids = {r["organization_id"] for r in results}

    for pending in pending_orgs:
        org_id = pending.get("id")
        if not org_id or org_id in existing_ids:
            continue

        try:
            org = toolkit.get_action("organization_show")(context, {"id": org_id})
        except toolkit.ObjectNotFound:
            org = {"id": org_id, "title": org_id, "name": org_id}

        status = pending.get("status", "pending").capitalize()
        handler = pending.get("handler")
        request_date_str = _format_iso_date(pending.get("request_date"))

        message_parts = [f"{status} via Auth0"]
        if handler:
            message_parts.append(f"by {handler}")
        if request_date_str:
            message_parts.append(f"on {request_date_str}")

        message = " ".join(message_parts)

        results.append({
            "organization_name": org["name"],
            "organization_display_name": org["title"],
            "organization_id": org_id,
            "state": pending.get("status", "pending"),
            "role": None,
            "message": message,
            "request_date": request_date_str,
            "handling_date": _format_iso_date(pending.get("handling_date")),
            "handled_by": pending.get("handler"),
        })

    return results


def member_requests_status(context, data_dict):
    ''' Admins wil see a list of member requests for a user
    '''
    logic.check_access('member_requests_status', context, data_dict)

    user = data_dict.get('mrequest_user', None)

    user_object = model.User.get(user)
    # Return current state for memberships for all organizations for the user
    # in context. (last modified date)
    membership_requests = []
    organizations = model.Session.query(model.Group).all()
    for org in organizations:
        if not org.is_organization:
            continue
        request = model.Session.query(model.Member).filter(
            or_(model.Member.state == 'active',
                model.Member.state == 'pending')).filter(
            model.Member.table_name == "user").filter(
            model.Member.group_id == org.id).filter(
            model.Member.table_id == user_object.id).first()
        if request:
            membership_requests.append(request)
    return _membership_request_list_dictize(membership_requests, context)


def member_requests_list(context, data_dict):
    ''' Organization admins/editors will see a list of member requests to be approved.
    :param group: name of the group (optional)
    :type group: string
    '''
    logic.check_access('member_requests_list', context, data_dict)

    user = context.get('user', None)
    user_object = model.User.get(user)
    is_sysadmin = authz.is_sysadmin(user)

    # ALL members with pending state only
    query = model.Session.query(model.Member).filter(
        model.Member.table_name == "user").filter(model.Member.state == 'pending')

    if not is_sysadmin:
        admin_in_groups = model.Session.query(model.Member).filter(model.Member.state == "active")\
            .filter(model.Member.table_name == "user") \
            .filter(model.Member.capacity == 'admin').filter(model.Member.table_id == user_object.id)

        if admin_in_groups.count() <= 0:
            return []
        # members requests for this organization
        query = query.filter(model.Member.group_id.in_(
            admin_in_groups.values(model.Member.group_id)))

    group = data_dict.get('group', None)
    if group:
        group_object = model.Group.get(group)
        if group_object:
            query = query.filter(model.Member.group_id == group_object.id)

    members = query.all()

    return _member_list_dictize(members, context)


@logic.side_effect_free
def get_available_roles(context, data_dict=None):
    roles = logic.get_action("member_roles_list")(context, {})

    # If organization has no associated admin, then role editor is not
    # available
    organization_id = logic.get_or_bust(data_dict, 'organization_id')

    # Remove member role from the list
    roles = [role for role in roles]

    if organization_id:
        if get_organization_admins(organization_id):
            roles = [role for role in roles if role['value'] != 'editor']

    return roles


@logic.side_effect_free
def get_available_organizations(context, data_dict=None):
    data_dict = {}
    data_dict['all_fields'] = True
    data_dict['groups'] = []
    data_dict['type'] = 'organization'
    data_dict['include_extras'] = True

    all_orgs = toolkit.get_action('organization_list')({}, data_dict)
    orglist = toolkit.get_action("organization_list_for_user")(
        data_dict={
            "all_fields": True,
            "include_extras": True,
            "include_dataset_count": False,
            "include_groups": True,
        }
    )
    # Include or exclude organizations based on our include/exclude lists
    include = config.get('ckanext.ytp_request.include').split()
    exclude = config.get('ckanext.ytp_request.exclude').split()

    for org in all_orgs:
        if org not in orglist:
            org_allowed = True  # Assume it is allowed, unless it is marked as private
            for extra in org.get("extras"):
                if extra.get("key") == "Private" and extra.get("value") == "True":
                    org_allowed = False
            if org_allowed:
                orglist.append(org)


    if include:
        orglist = [o for o in orglist if o['name'] in include]
    orglist = [o for o in orglist if o['name'] not in exclude]

    return orglist


def _membership_request_list_dictize(obj_list, context):
    """Helper to convert member requests list to dictionary """
    result_list = []
    objs_with_group_id = (g for g in obj_list if g.group_id is not None)
    for obj in objs_with_group_id:
        member_dict = {}
        organization = model.Session.query(model.Group).get(obj.group_id)
        if not organization.is_organization:
            continue
        # Fetch the newest member_request associated to this membership (sort
        # by last modified field)
        member_request = model.Session.query(MemberRequest) \
            .filter(MemberRequest.membership_id == obj.id) \
            .order_by(desc(MemberRequest.request_date)).limit(1).first()
        # Filter out those with cancel state as there is no need to show them to the end user
        # Show however those with 'rejected' state as user may want to know about them
        # HUOM! If a user creates itself a organization has already a
        # membership but doesnt have a member_request
        member_dict['organization_name'] = organization.name
        member_dict['organization_display_name'] = organization.display_name
        member_dict['organization_id'] = obj.group_id
        # find existing role for the user
        member = model.Session.query(model.Member).\
            filter(model.Member.group_id == obj.group.id).\
            filter(model.Member.table_name == 'user').\
            filter(model.Member.id == obj.id).\
            filter(model.Member.state == "active").\
            first()

        trans = authz.roles_trans()

        def translated_capacity(capacity):
            try:
                return trans[capacity]
            except KeyError:
                return capacity

        if member:
            member_dict['role'] = translated_capacity(member.capacity)
        else:
            member_dict['role'] = 'member'
        #
        member_dict['state'] = 'active'
        member_dict['message'] = ''
        # We use the member_request state since there is also rejected and
        # cancel
        if member_request is not None and member_request.status != 'cancel':
            if member_request.status == 'active' and \
                 obj.state == 'deleted':
                    # Handle users that have been deleted elsewhere
                    # and not via this extension
                    continue
            member_dict['state'] = member_request.status
            member_dict['role'] = member_request.role
            member_dict['message'] = member_request.message
            member_dict['request_date'] = member_request.request_date.strftime(
                "%d - %b - %Y")
            member_dict['mid'] = obj.id
            if member_request.handling_date:
                member_dict['handling_date'] = member_request.handling_date.strftime(
                    "%d - %b - %Y")
                member_dict['handled_by'] = member_request.handled_by
        if member_request is None or member_request.status != 'cancel':
            result_list.append(member_dict)
    return result_list


def _member_list_dictize(obj_list, context, sort_key=lambda x: x['group_id'], reverse=False):
    """ Helper to convert member list to dictionary """
    result_list = []
    for obj in obj_list:
        member_dict = model_dictize.member_dictize(obj, context)
        user = model.Session.query(model.User).get(obj.table_id)

        if obj.group is not None:
            member_dict['group_name'] = obj.group.name
            member_dict['group_display_name'] = obj.group.title
        member_dict['role'] = obj.capacity
        # Member request must always exist since state is pending. Fetch just
        # the latest
        member_request = model.Session.query(MemberRequest).filter(MemberRequest.membership_id == obj.id)\
            .filter(MemberRequest.status == 'pending').order_by(MemberRequest.request_date.desc()).limit(1).first()
        # This should never happen but..
        my_date = ""
        if member_request is not None:
            my_date = member_request.request_date.strftime("%d - %b - %Y")

        member_dict['request_date'] = my_date
        member_dict['mid'] = obj.id

        if user.email is not None:
            member_dict['user_name'] = user.name
            member_dict['fullname'] = user.fullname
        member_dict['user_email'] = user.email
        member_dict['message'] = member_request.message
        result_list.append(member_dict)
    return sorted(result_list, key=sort_key, reverse=reverse)


@logic.side_effect_free
def organization_list_without_memberships(context, data_dict):

    model = context['model']
    if data_dict.get('id'):
        user_obj = model.User.get(data_dict['id'])
        if not user_obj:
            raise NotFound
        user = user_obj.name
    else:
        user = context['user']

    logic.check_access('organization_list_without_memberships', context, data_dict)

    user_id = authz.get_user_id_for_username(user, allow_none=True)
    if not user_id:
        return []

    subquery = model.Session.query(model.Group.id)\
        .filter(model.Member.table_name == 'user')\
        .filter(model.Member.table_id == user_id)\
        .filter(model.Group.id == model.Member.group_id)\
        .filter(model.Member.state.in_(['active', 'pending'])) \
        .distinct(model.Group.id) \
        .filter(model.Group.is_organization == True)  # noqa

    groups = model.Session.query(model.Group) \
        .filter(model.Group.id.notin_(subquery)).all()

    return model_dictize.group_list_dictize(groups,
                                            context,
                                            with_package_counts=toolkit.asbool(data_dict.get('include_dataset_count')))
