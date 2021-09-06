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
    auth.signature,
    format='%(f_user_id)s',
    migrate=settings.migrate)

db.define_table('t_user_status_archive',db.t_user_status,Field('current_record','reference t_user_status',readable=False,writable=False))
