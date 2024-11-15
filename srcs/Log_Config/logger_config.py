
import os
import logging


def configure_logger(logger_name,logger_path,logger_level):

    if os.path.exists(logger_path):
        os.remove(logger_path)


    logger = logging.getLogger(logger_name)
    logger.setLevel(logger_level)

    handler = logging.FileHandler(logger_path)
    
    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    handler.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(handler)
    return logger

if __name__ == "__main__":
    logger = configure_logger("test","test.log",logging.INFO)
    logger1 = logging.getLogger("test")
    logger1.log(logging.INFO,"Test")


