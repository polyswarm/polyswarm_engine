import os

os.environ['PSENGINE_BROKER_URL'] = 'memory://localhost/'
os.environ['PSENGINE_TASK_ALWAYS_EAGER'] = '1'
