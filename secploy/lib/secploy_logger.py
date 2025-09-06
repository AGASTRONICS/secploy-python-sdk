import logging

def setup_logger(log_level="INFO"):
    
    if log_level.upper() == "NONE":
        logging.disable(logging.CRITICAL)
        return
    
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    logging.basicConfig(
        level=numeric_level,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    

secploy_logger = logging.getLogger(__name__)