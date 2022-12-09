class Config:
    log_path = "./log/flask.log"
    log_format = "[%(asctime)s][%(module)s:%(lineno)d][%(levelname)s][%(thread)d] - %(message)s"
    secret_key = 'Htek20180905'
    sql_root_name = 'root'
    sql_root_pass = 'HtekRPS2017'
    sql_auth_db = 'http'
    sql_port = '3306'
    sql_url = f'mysql+pymysql://{sql_root_name}:{sql_root_pass}@127.0.0.1:{sql_port}/{sql_auth_db}'
    register_key = 'Htek20180905'
