from gluon.storage import Storage
settings = Storage()

settings.migrate = True
settings.title = 'Cyweemotion Tools'
settings.subtitle = 'cwm apis'
settings.author = 'ChuYuan Chiang'
settings.author_email = 'chuyuan.chiang@cyweemotion.com'
settings.keywords = None
settings.description = None
settings.layout_theme = 'Default'
settings.database_uri = 'mysql://root:123456@127.0.0.1/dio'
settings.security_key = 'd6d14582-0335-417f-800f-56c4ef280650'
settings.email_server = 'localhost'
settings.email_sender = 'you@example.com'
settings.email_login = None
settings.login_method = 'local'
settings.login_config = None
settings.plugins = []
settings.use_test_db = False
