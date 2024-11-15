from aalpy.base import SUL

class FailSafeSUL(SUL):

    """
    This class is only required to correctly monitor performed steps on the SUL
    """

    def __init__(self):
        super().__init__()
        self.performed_steps_in_query = 0
