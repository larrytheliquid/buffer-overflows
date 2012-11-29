# Add our locally installed libs to the search path.
import sys
sys.path.append('lib/local/lib/python%s.%s/site-packages'
                % (sys.version_info.major, sys.version_info.minor))
