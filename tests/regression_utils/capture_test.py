import sys

from absl import app
from absl.testing import absltest

from tests.regression_utils import capture

EXAMPLE_FILENAME1 = 'example_file1'
EXAMPLE_FILENAME2 = 'example_file2'


class TestReferenceCaptureDecorators(absltest.TestCase):

  @capture.stdout
  def testStdout(self):
    print("asdf123")
    print("asdf543")

  @capture.stderr
  def testStderr(self):
    print("asdf123", file=sys.stderr)
    print("asdf543", file=sys.stderr)

  @capture.stderr
  @capture.stdout
  def testStdoutAndStderr(self):
    print("asdf123")
    print("asdf543", file=sys.stderr)

  @capture.files((EXAMPLE_FILENAME1, EXAMPLE_FILENAME2))
  def testFileCapture(self):
    print("asdf123")
    with open(EXAMPLE_FILENAME1, 'w') as f1, open(EXAMPLE_FILENAME2, 'w') as f2:
      f1.write("asdf40044")
      f2.write("asdf30094")
      f1.write("asdf40044")
      f2.write("asdf30094")


def main(unused_argv):
  absltest.main()


if __name__ == '__main__':
  app.run(main)
