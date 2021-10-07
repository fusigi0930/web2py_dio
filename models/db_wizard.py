### we prepend t_ to tablenames and f_ to fieldnames for disambiguity


########################################
db.define_table('t_user_status',
    Field('f_user_id', type='integer',
          label=T('User Id')),
    Field('f_status', type='integer',
          label=T('Status')),
    Field('f_expire_time', type='datetime',
          label=T('Expire Time')),
    Field('f_permission', type='integer',
          label=T('Permission')),
    Field('f_uuid', type='string',
          label=T('uuid')),
    Field('f_email', type='string',
          label=T('email')),
    Field('f_comment', type='string',
          label=T('comments')),
    auth.signature,
    format='anonymous',
    migrate=settings.migrate)

db.define_table('t_user_status_archive',db.t_user_status,Field('current_record','reference t_user_status',readable=False,writable=False))

db.define_table('t_log',
    Field('f_uuid', type='string', label=T('uuid')),
    Field('f_source', type='string', label=T('source ip')),
    Field('f_req_time', type='datetime', label=T('require time')),
    Field('f_cmdline', type='string', label=T('command line')),
    Field('f_verinfo', type='string', label=T('version info')),
    Field('f_status', type='integer', label=T('status')),
    auth.signature,
    format='anonymous',
    migrate=settings.migrate)

db.define_table('t_log_archive',db.t_user_status,Field('current_record','reference t_log',readable=False,writable=False))
