
def logerror(exception):
    print("unhandled exception: ", exception)

def logerrortext(errortext):
    print("error occurred: ", errortext)

class DatabaseError(RuntimeError):
    def __init__(self, arg):
        self.args = arg

class LogDatabaseError(RuntimeError):
  def __init__(self, arg):
    self.args = arg
