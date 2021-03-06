# -*- coding: utf-8 -*-
### required - do no delete
def user(): return dict(form=auth())
### end requires

def error():
    return dict()

auth.settings.actions_disabled.append('register')
auth.settings.login_url = URL('admin', 'user/login')
@auth.requires_login()
@auth.requires_permission('edit', db.t_user_status)
def user_status_manage():
    form = SQLFORM.smartgrid(db.t_user_status,onupdate=auth.archive)
    #form = None
    showmsg = 'group id: {} '.format(auth.id_group('admin'))
    showmsg = showmsg + 'is login: {} '.format(auth.is_logged_in())
    showmsg = showmsg + 'has permission: {} '.format(auth.has_permission('edit', db.t_user_status, 0, auth.user.id))
    return locals()

auth.settings.actions_disabled.append('register')
auth.settings.login_url = URL('admin', 'user/login')
@auth.requires_login()
@auth.requires_permission('edit', db.auth_membership)
def user_group():
    form = SQLFORM.smartgrid(db.auth_membership,onupdate=auth.archive)
    #form = None
    showmsg = 'group id: {} '.format(auth.id_group('admin'))
    showmsg = showmsg + 'is login: {} '.format(auth.is_logged_in())
    showmsg = showmsg + 'has permission: {} '.format(auth.has_permission('edit', db.auth_membership, 0, auth.user.id))
    return locals()

auth.settings.actions_disabled.append('register')
auth.settings.login_url = URL('admin', 'user/login')
@auth.requires_login()
@auth.requires_permission('edit', db.auth_membership)
def logs():
    form = SQLFORM.smartgrid(db.t_log,onupdate=auth.archive)
    #form = None
    showmsg = 'group id: {} '.format(auth.id_group('admin'))
    showmsg = showmsg + 'is login: {} '.format(auth.is_logged_in())
    showmsg = showmsg + 'has permission: {} '.format(auth.has_permission('edit', db.auth_membership, 0, auth.user.id))
    return locals()
