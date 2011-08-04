
class RackerTools:
    
    def __init__(self, args):
        self.tool = args.pop(0)
        self.args = args

        self.module = __import__('tools.'+self.tool, globals(), locals(), ["tools"])

    def Run(self):
        self.module.run(self.args)

class RackerToolsException(BaseException):
    pass

