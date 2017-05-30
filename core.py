# Standard imports
from urllib2 import Request, urlopen, HTTPError
from urllib import urlencode
from json import dumps, loads
from StringIO import StringIO
from gzip import GzipFile
from base64 import b64encode
from threading import _MainThread, current_thread, Thread
from sys import stdout
from os import environ
from operator import isCallable  # IGNORE:no-name-in-module

# Django imports
from django.conf import settings


STDOUT_LOG_INFO = 0
STDOUT_LOG_WARNING = 1


class TerminalFontColors(object):  # IGNORE:too-few-public-methods
    response = '\033[32m'
    request = '\033[34m'
    response_code = '\033[35m'
    callback = '\033[31m'
    warning = '\033[93m'

    @staticmethod
    def wrap_text(text, text_type):
        return '%s%s\033[0m' % (text_type, unicode(text))


def stdout_debug_log(message, severity=STDOUT_LOG_INFO, *args, **kwargs):
    # NOTE: Printing messages when inside thread other than MainThread
    #       is discouraged
    if not isinstance(current_thread(), _MainThread):
        return

    if severity == STDOUT_LOG_INFO and (
        not settings.DEBUG and not environ.get('BITCALL_LOGGING')
    ):
        return

    logged_text = (
        message
        if not hasattr(message, '__call__')
        else message(*args, **kwargs)
    )

    if severity == STDOUT_LOG_WARNING:
        print TerminalFontColors.wrap_text(
            '[WARNING]: %s' % logged_text, TerminalFontColors.warning
        )
    else:
        print logged_text

    # Flush is required to output complete messages to preserve readability.
    stdout.flush()


class PayloadWithError(object):  # IGNORE:too-few-public-methods
    def __init__(self, error):
        self.error = error

    def __nonzero__(self):
        return False


class ForeignServiceParametersStorage(dict):
    def __init__(self, *args, **kwargs):
        self.is_simple_dict_mode = False

        super(ForeignServiceParametersStorage, self).__init__(*args, **kwargs)

        raw_items = super(ForeignServiceParametersStorage, self).items()
        for raw_item in raw_items:
            self.__delitem__(raw_item[0])
            self.__setitem__(raw_item[0], raw_item[1])

    def __setitem__(self, key, value):
        if not self.is_simple_dict_mode:
            value_list = self.get(key)
            if not value_list:
                value_list = []
                super(ForeignServiceParametersStorage, self).__setitem__(
                    key, value_list
                )

            value_list.append(value)
        else:
            super(ForeignServiceParametersStorage, self).__setitem__(
                key, [value]
            )

    def enable_simple_dict_mode(self):
        self.is_simple_dict_mode = True

    def enable_parameters_storage_mode(self):
        self.is_simple_dict_mode = False

    def items(self):
        raw_items = super(ForeignServiceParametersStorage, self).items()
        processed_items = []
        for processed_item in raw_items:
            for value in processed_item[1]:
                processed_items.append((processed_item[0], value))

        return processed_items

    def viewitems(self):
        return self.items()


def foreign_service_request(
    url,
    parameters=None,
    payload=None,
    headers=None,
    method=None,
    form=None,
    use_compression=True
):
    assert (
        payload and not form
    ) or (
        not payload and form
    ) or (
        not payload and not form
    )

    if form:
        content_type = 'application/x-www-form-urlencoded'
        data = urlencode(form)
    else:
        content_type = 'application/json'
        data = dumps(payload, separators=(',', ':')) if payload else None

    if parameters:
        # NOTE: ensuring unicode parameters are properly encoded
        # NOTE: as we may be dealing either with
        #       ForeignServiceParametersStorage instance or with simple Python
        #       dict - processing data in the form of tuples that urlencode
        #       understands is the simplest and safest way.
        parameters = tuple(
            (
                (
                    parameter_set[0].encode('utf-8')
                    if isinstance(parameter_set[0], (str, unicode))
                    else parameter_set[0]
                ),
                (
                    parameter_set[1].encode('utf-8')
                    if isinstance(parameter_set[1], (str, unicode))
                    else parameter_set[1]
                )
            ) for parameter_set in parameters.viewitems()
        )

    http_request = Request(
        url=url + ('?%s' % urlencode(parameters) if parameters else ''),
        data=data,
        headers={'Content-Type': content_type, 'Accept': 'application/json'}
    )

    if use_compression:
        http_request.add_header('Accept-encoding', 'gzip')

    if headers:
        for header in headers.viewitems():
            http_request.add_header(header[0], header[1])

    if method:
        http_request.get_method = lambda: method

    try:
        current_response = urlopen(http_request)

        # NOTE: If server returned 204 (no content) - no need to parse response
        if current_response.getcode() != 204:
            if current_response.info().get('Content-Encoding') == 'gzip':
                string_io_stream = StringIO(current_response.read())
                uncompressed_content = GzipFile(fileobj=string_io_stream)
                response_data = loads(uncompressed_content.read())
                string_io_stream.close()
                uncompressed_content.close()
            else:
                response_data = loads(current_response.read())
        else:
            response_data = None

        current_response.close()

        return response_data
    except HTTPError, error:
        stdout_debug_log(
            'HTTP request failed [%s]' % (http_request.get_full_url()),
            STDOUT_LOG_WARNING
        )

        from raven.contrib.django.raven_compat.models import client

        context = {}

        error_message = error.read()
        try:
            string_io_stream = StringIO(error_message)
            uncompressed_error_message = GzipFile(fileobj=string_io_stream)
            context['message (uncompressed)'] = (
                uncompressed_error_message.read()
            )
            context['message (base64)'] = (
                b64encode(context['message (uncompressed)']) or 'EMPTY'
            )
            context['message (uncompressed)'] = (
                context['message (uncompressed)'] or 'EMPTY'
            )
            uncompressed_error_message.close()
        except IOError:
            context['message (raw)'] = error_message
            context['message (base64)'] = (
                b64encode(context['message (raw)']) or 'EMPTY'
            )
            context['message (raw)'] = (
                context['message (raw)'] or 'EMPTY'
            )

            # NOTE: reraising original exception so that we report it and not
            #       the second one
            try:
                raise error
            except HTTPError:
                pass
        finally:
            string_io_stream.close()

        client.extra_context(context)
        client.captureException()

        return PayloadWithError(error.code)


class ForeignServiceRequestThread(Thread):
    def __init__(self):
        super(ForeignServiceRequestThread, self).__init__()
        self.response = None

        self.url = None
        self.parameters = None
        self.payload = None
        self.headers = None
        self.method = None
        self.use_compression = True

    def set_configuration(
        self,
        url,
        parameters=None,
        payload=None,
        headers=None,
        method=None,
        use_compression=True
    ):
        self.url = url
        self.parameters = parameters
        self.payload = payload
        self.headers = headers
        self.method = method
        self.use_compression = use_compression

    def run(self):
        self.response = foreign_service_request(
            url=self.url,
            parameters=self.parameters,
            payload=self.payload,
            headers=self.headers,
            method=self.method,
            use_compression=self.use_compression
        )


class PaginatedForeignServiceRequest(object):
    def __init__(
        self,
        pagination_callback,
        url,
        parameters=None,
        payload=None,
        headers=None,
        method=None,
        use_compression=True
    ):
        assert isCallable(pagination_callback)

        self.pagination_callback = pagination_callback

        self.perform_foreign_service_request(
            url=url,
            parameters=parameters,
            payload=payload,
            headers=headers,
            method=method,
            use_compression=use_compression
        )

    def perform_foreign_service_request(
        self,
        url=None,
        parameters=None,
        payload=None,
        headers=None,
        method=None,
        use_compression=True
    ):
        self.url = url
        self.parameters = parameters
        self.payload = payload
        self.headers = headers
        self.method = method
        self.use_compression = use_compression

        self.networking_thread = ForeignServiceRequestThread()
        self.networking_thread.set_configuration(
            url=self.url,
            parameters=self.parameters,
            payload=self.payload,
            headers=self.headers,
            method=self.method,
            use_compression=self.use_compression
        )
        self.networking_thread.start()

        self.next_page_exists = True

    def get_response(self):
        assert self.networking_thread

        if self.next_page_exists:
            self.networking_thread.join()
            response = self.networking_thread.response

            if self.pagination_callback(self, response):
                self.perform_foreign_service_request(
                    url=self.url,
                    parameters=self.parameters,
                    payload=self.payload,
                    headers=self.headers,
                    method=self.method,
                    use_compression=self.use_compression
                )
            else:
                self.next_page_exists = False
        else:
            return

        return response
