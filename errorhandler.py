
def logerror(exception):
  print("unhandled exception: ", exception)

class DatabaseError(RuntimeError):
  def __init__(self, arg):
    self.args = arg
