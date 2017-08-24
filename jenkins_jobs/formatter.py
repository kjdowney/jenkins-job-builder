#!/usr/bin/env python
# Copyright (C) 2015 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Manage interpolation of JJB variables into template strings.

import logging
from pprint import pformat
import re
from string import Formatter

from jenkins_jobs.errors import JenkinsJobsException

logger = logging.getLogger(__name__)


def deep_format(obj, paramdict, allow_empty=False):
    """Apply the paramdict via str.format() to all string objects found within
       the supplied obj. Lists and dicts are traversed recursively."""
    # YAML serialisation was originally used to achieve this, but that places
    # limitations on the values in paramdict - the post-format result must
    # still be valid YAML (so substituting-in a string containing quotes, for
    # example, is problematic).
    if hasattr(obj, 'format'):
        try:
            ret = CustomFormatter(allow_empty).format(obj, **paramdict)
        except KeyError as exc:
            missing_key = exc.args[0]
            desc = "%s parameter missing to format %s\nGiven:\n%s" % (
                missing_key, obj, pformat(paramdict))
            raise JenkinsJobsException(desc)
        except Exception:
            logging.error("Problem formatting with args:\nallow_empty:"
                          "%s\nobj: %s\nparamdict: %s" %
                          (allow_empty, obj, paramdict))
            raise

    elif isinstance(obj, list):
        ret = type(obj)()
        for item in obj:
            ret.append(deep_format(item, paramdict, allow_empty))
    elif isinstance(obj, dict):
        ret = type(obj)()
        for item in obj:
            try:
                ret[CustomFormatter(allow_empty).format(item, **paramdict)] = \
                    deep_format(obj[item], paramdict, allow_empty)
            except KeyError as exc:
                missing_key = exc.args[0]
                desc = "%s parameter missing to format %s\nGiven:\n%s" % (
                    missing_key, obj, pformat(paramdict))
                raise JenkinsJobsException(desc)
            except Exception:
                logging.error("Problem formatting with args:\nallow_empty:"
                              "%s\nobj: %s\nparamdict: %s" %
                              (allow_empty, obj, paramdict))
                raise
    else:
        ret = obj
    return ret

# Custom formatter used to recursively perform nested string substitution.
class NestedExpansionFormatter(Formatter):
    # Override of base _vformat to enable nested string substitution.
    def _vformat(self, format_string, args, kwargs, used_args, recursion_depth):
        if recursion_depth < 0:
            raise ValueError('Max string recursion exceeded')
        result = []
        for literal_text, field_name, format_spec, conversion in \
                self.parse(format_string):

            # output the literal text
            if literal_text:
                result.append(literal_text)

            # if there's a field, output it
            if field_name is not None:
                # this is some markup, find the object and do
                #  the formatting

                # given the field_name, find the object it references
                #  and the argument it came from
                obj, arg_used = self.get_field(field_name, args, kwargs)
                used_args.add(arg_used)

                # do any conversion on the resulting object
                obj = self.convert_field(obj, conversion)

                # expand the format spec, if needed
                format_spec = self._vformat(format_spec, args, kwargs,
                                            used_args, recursion_depth-1)

                # format the object
                obj = self.format_field(obj, format_spec)

                # Attempt nested expansion on field.
                result.append(self.vformat(obj, args, kwargs))

        return ''.join(result)

class CustomFormatter(NestedExpansionFormatter):
    """
    Custom formatter to allow non-existing key references when formatting a
    string
    """
    _expr = '{({{)*(?:obj:)?(?P<key>\w+)(?:\|(?P<default>[\w\s]*))?}(}})*'

    def __init__(self, allow_empty=False):
        super(CustomFormatter, self).__init__()
        self.allow_empty = allow_empty

    def vformat(self, format_string, args, kwargs):
        matcher = re.compile(self._expr)

        # special case of returning the object if the entire string
        # matches a single parameter
        try:
            result = re.match('^%s$' % self._expr, format_string)
        except TypeError:
            return format_string.format(**kwargs)
        if result is not None:
            try:
                return kwargs[result.group("key")]
            except KeyError:
                pass

        # handle multiple fields within string via a callback to re.sub()
        def re_replace(match):
            key = match.group("key")
            default = match.group("default")

            if default is not None:
                if key not in kwargs:
                    return default
                else:
                    return "{%s}" % key
            return match.group(0)

        format_string = matcher.sub(re_replace, format_string)

        return super.vformat(self, format_string, args, kwargs)

    def get_value(self, key, args, kwargs):
        try:
            return super.get_value(self, key, args, kwargs)
        except KeyError:
            if self.allow_empty:
                logger.debug(
                    'Found uninitialized key %s, replaced with empty string',
                    key
                )
                return ''
            raise
