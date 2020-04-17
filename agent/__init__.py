"""
<filename>.py

Author: Desmond Tan
"""

#                                                   Imports                                                            #


#                                                   Constants                                                          #


#                                                   Functions                                                          #


#                                                    Tests                                                             #

class TestSuite(object):
    def __init__(self):
        self.all_test_passed = True

        # calling all test methods...
        test_method_names = [method for method in dir(self) if callable(getattr(self, method)) if
                             method.startswith('test')]
        for method in test_method_names:
            getattr(self, method)()

        if self.all_test_passed:
            print 'All test passed'

    def test_function(self):
        pass


#                                                     Main                                                             #

def main():
    pass


if __name__ == '__main__':
    TestSuite()
    main()
