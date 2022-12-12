class Config:
    log_path = "./log/flask.log"
    log_format = "[%(asctime)s][%(module)s:%(lineno)d][%(levelname)s][%(thread)d] - %(message)s"
    secret_key = 'Http20221212'
    sql_root_name = 'root'
    sql_root_pass = 'Http20121212'
    sql_auth_db = 'http'
    sql_port = '3306'
    sql_url = f'mysql+pymysql://{sql_root_name}:{sql_root_pass}@127.0.0.1:{sql_port}/{sql_auth_db}'
    register_key = 'Http20121212'
