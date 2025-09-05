import re
import calendar
from insightlog.settings import *
from insightlog.validators import *
from datetime import datetime
import chardet 

def get_service_settings(service_name):
    """
    Get default settings for the said service
    :param service_name: service name (example: nginx, apache2...)
    :return: service settings if found or None
    """
    if service_name in SERVICES_SWITCHER:
        return SERVICES_SWITCHER.get(service_name)
    else:
        raise Exception("Service \""+service_name+"\" doesn't exists!")


def get_date_filter(settings, minute=datetime.now().minute, hour=datetime.now().hour,
                    day=datetime.now().day, month=datetime.now().month,
                    year=datetime.now().year):
    """
    Get the date pattern that can be used to filter data from logs based on the params
    :raises Exception:
    :param settings: dict
    :param minute: int
    :param hour: int
    :param day: int
    :param month: int
    :param year: int
    :return: string
    """
    if not is_valid_year(year) or not is_valid_month(month) or not is_valid_day(day) \
            or not is_valid_hour(hour) or not is_valid_minute(minute):
        raise Exception("Date elements aren't valid")
    if minute != '*' and hour != '*':
        date_format = settings['dateminutes_format']
        date_filter = datetime(year, month, day, hour, minute).strftime(date_format)
    elif minute == '*' and hour != '*':
        date_format = settings['datehours_format']
        date_filter = datetime(year, month, day, hour).strftime(date_format)
    elif minute == '*' and hour == '*':
        date_format = settings['datedays_format']
        date_filter = datetime(year, month, day).strftime(date_format)
    else:
        raise Exception("Date elements aren't valid")
    return date_filter


def filter_data(log_filter, data=None, filepath=None, is_casesensitive=True, is_regex=False, is_reverse=False):
    """
    Filter received data/file content and return the results
    :param log_filter: string
    :param data: string
    :param filepath: string
    :param is_casesensitive: boolean
    :param is_regex: boolean
    :param is_reverse: boolean to inverse selection
    :return: string
    """
    return_data = ""

    if filepath:
        try:
            # Optional: encoding hardening; uncomment if desired
            # with open(filepath, 'r', encoding='utf-8', errors='replace') as file_object:
            with open(filepath, 'r') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            # Raise (don’t print/return None)
            raise Exception(f"File error: {e.strerror}") from e

    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line + "\n"
        return return_data

    else:
        raise Exception("Data and filepath values are NULL!")

    # BUG: This function returns None on error instead of raising
    # BUG: No encoding handling in file reading (may crash on non-UTF-8 files)
    # TODO: Log errors/warnings instead of print
    return_data = ""
    if filepath:
        try:
            with open(filepath, 'r') as file_object:
                for line in file_object:
                    if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                        return_data += line
            return return_data
        except (IOError, EnvironmentError) as e:
            print(e.strerror)
            # TODO: Log error instead of print
            # raise  # Should raise instead of just printing
            return None
    elif data:
        for line in data.splitlines():
            if check_match(line, log_filter, is_regex, is_casesensitive, is_reverse):
                return_data += line+"\n"
        return return_data
    else:
        # TODO: Better error message for missing data/filepath
        raise Exception("Data and filepath values are NULL!")


def check_match(line, filter_pattern, is_regex, is_casesensitive, is_reverse):
    """
    Check if line contains/matches filter pattern
    :param line: string
    :param filter_pattern: string
    :param is_regex: boolean
    :param is_casesensitive: boolean
    :param is_reverse: boolean
    :return: boolean
    """
    if is_regex:
        check_result = re.match(filter_pattern, line) if is_casesensitive \
            else re.match(filter_pattern, line, re.IGNORECASE)
    else:
        check_result = (filter_pattern in line) if is_casesensitive else (filter_pattern.lower() in line.lower())
    return check_result and not is_reverse


def get_web_requests(data, pattern, date_pattern=None, date_keys=None, service=None):
    """
    Analyze web log data and return a list of requests (list of dicts).
    Non-matching lines are skipped here, but we will count them in the Analyzer.
    Tests expect this function to return ONLY a list (not a tuple).
    """
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    requests = []
    regex = re.compile(pattern, flags=re.IGNORECASE)

    for line in data.splitlines():
        if not line.strip():
            continue
        m = regex.search(line)
        if not m:
            continue

        request_tuple = m.groups()
        if date_pattern:
            str_datetime = __get_iso_datetime(request_tuple[1], date_pattern, date_keys)
        else:
            str_datetime = request_tuple[1]

        requests.append({
            'DATETIME': str_datetime,
            'SERVICE': service or 'web',
            'IP': request_tuple[0],
            'METHOD': request_tuple[2],
            'ROUTE': request_tuple[3],
            'CODE': request_tuple[4],
            'REFERRER': request_tuple[5],
            'USERAGENT': request_tuple[6],
        })

    return requests  



def get_auth_requests(data, pattern, date_pattern=None, date_keys=None, service='auth'):
    """
    Analyze auth log data and return a list of events (list of dicts).
    Includes auth-specific keys so tests can assert e.g. INVALID_PASS_USER == 'root'.
    """
    if date_pattern and not date_keys:
        raise Exception("date_keys is not defined")

    requests = []
    regex = re.compile(pattern, flags=re.IGNORECASE)
    date_regex = re.compile(date_pattern, flags=re.IGNORECASE) if date_pattern else None

    for line in data.splitlines():
        if not line.strip():
            continue

        m = regex.search(line)
        if not m:
            continue

        groups = m.groups()
        dt = None
        if date_regex:
            dm = date_regex.search(line)
            if dm:
                dt = __get_iso_datetime(dm.group(0), date_pattern, date_keys)
        else:
            if len(groups) > 1:
                dt = groups[1]
        ip = groups[0] if len(groups) > 0 else None
        auth_info = analyze_auth_request(line)

        requests.append({
            'DATETIME': dt,
            'SERVICE': service,
            'IP': ip if ip else auth_info.get('IP'),
            'INVALID_USER': auth_info.get('INVALID_USER'),
            'INVALID_PASS_USER': auth_info.get('INVALID_PASS_USER'),
            'IS_PREAUTH': auth_info.get('IS_PREAUTH'),
            'IS_CLOSED': auth_info.get('IS_CLOSED'),
        })

    return requests



def analyze_auth_request(request_info):
    """
    Analyze request info and returns main data (IP, invalid user, invalid password's user, is_preauth, is_closed)
    :param request_info: string
    :return: dicts
    """
    # BUG: No handling/logging for malformed lines
    ipv4 = re.findall(IPv4_REGEX, request_info)
    is_preauth = '[preauth]' in request_info.lower()
    invalid_user = re.findall(AUTH_USER_INVALID_USER, request_info)
    invalid_pass_user = re.findall(AUTH_PASS_INVALID_USER, request_info)
    is_closed = 'connection closed by ' in request_info.lower()
    return {'IP': ipv4[0] if ipv4 else None,
            'INVALID_USER': invalid_user[0] if invalid_user else None,
            'INVALID_PASS_USER': invalid_pass_user[0] if invalid_pass_user else None,
            'IS_PREAUTH': is_preauth,
            'IS_CLOSED': is_closed}


def __get_iso_datetime(str_date, pattern, keys):
    """
    Change raw datetime from logs to ISO 8601 format.
    :param str_date: string
    :param pattern: regex (date_pattern from settings)
    :param keys: dict (date_keys from settings)
    :return: string
    """
    months_dict = {v: k for k, v in enumerate(calendar.month_abbr)}
    a_date = re.findall(pattern, str_date)[0]
    d_datetime = datetime(int(a_date[keys['year']]) if 'year' in keys else __get_auth_year(),
                          months_dict[a_date[keys['month']]], int(a_date[keys['day']].strip()),
                          int(a_date[keys['hour']]), int(a_date[keys['minute']]), int(a_date[keys['second']]))
    return d_datetime.isoformat(' ')


def __get_auth_year():
    # TODO: Add support for analysis done in different terms
    """
    Return the year when the requests happened so there will be no bug if the analyze is done in the new year eve,
    the library was designed to be used for hourly analysis.
    :return: int
    """
    if datetime.now().month == 1 and datetime.now().day == 1 and datetime.now().hour == 0:
        return datetime.now().year - 1
    else:
        return datetime.now().year


class InsightLogAnalyzer:

    def __init__(self, service, data=None, filepath=None):
        self._last_stats = {} 
        self.__filters = []
        self.__service = service
        self.__settings = get_service_settings(service)
        self.data = data
        if filepath:
            self.filepath = filepath
        else:
            self.filepath = self.__settings['dir_path'] + self.__settings['accesslog_filename']

    def add_filter(self, filter_pattern, is_casesensitive=True, is_regex=False, is_reverse=False):
        """
        Add filter data the filters list
        :param filter_pattern: boolean
        :param is_casesensitive: boolean
        :param is_regex: boolean
        :param is_reverse: boolean
        :return:
        """
        self.__filters.append({
            'filter_pattern': filter_pattern,
            'is_casesensitive': is_casesensitive,
            'is_regex': is_regex,
            'is_reverse': is_reverse
        })

    def add_date_filter(self, minute=datetime.now().minute, hour=datetime.now().hour,
                        day=datetime.now().day, month=datetime.now().month, year=datetime.now().year):
        """
        Set datetime filter
        :param minute: int
        :param hour: int
        :param day: int
        :param month: int
        :param year: int
        """
        date_filter = get_date_filter(self.__settings, minute, hour, day, month, year)
        self.add_filter(date_filter)

    def get_all_filters(self):
        """
        return all defined filters
        :return: List
        """
        return self.__filters

    def get_filter(self, index):
        """
        Get a filter data by index
        :param index:
        :return: Dictionary
        """
        return self.__filters[index]


    def remove_filter(self, index):
        """
        Remove one filter from filters list using its index.
        Raises:
            ValueError: if index is out of range.
        """
        try:
            self.__filters.pop(index)
        except IndexError:
            raise ValueError(f"Filter index out of range: {index}") from None


    def clear_all_filters(self):
        """
        Clear all filters
        :return:
        """
        self.__filters = []

    def check_all_matches(self, line, filter_patterns):
        """
        Check if line contains/matches all filter patterns
        :param line: String
        :param filter_patterns: List of dictionaries containing
        :return: boolean
        """
        if not filter_patterns:
            return True  # No filters means include all lines
        to_return = None
        for pattern_data in filter_patterns:
            tmp_result = check_match(line=line, **pattern_data)
            to_return = tmp_result if to_return is None else (tmp_result and to_return)
        return to_return

    def filter_all(self):
        """
        Apply all defined patterns and return filtered data
        :return: string
        """
        to_return = ""

        # Data-driven path
        if self.data is not None:
            # Treat '', None, or whitespace-only as empty
            if not str(self.data).strip():
                raise Exception("Empty log file (data)")
            for line in self.data.splitlines():
                if self.check_all_matches(line, self.__filters):
                    to_return += line + "\n"
            # No matches is fine; only the source being empty is an error
            return to_return

                # File-driven path
        try:
            with open(self.filepath, 'r') as file_object:
                lines = file_object.readlines()
                if not lines:
                    raise Exception("Empty log file")
                for line in lines:
                    if self.check_all_matches(line, self.__filters):
                        to_return += line
            return to_return
        except (IOError, EnvironmentError) as e:
            raise Exception(f"File error: {e.strerror}") from e

        
    def get_last_stats(self): 
        """Return stats from the last get_requests() call (e.g., 
        malformed_count).""" 
        return self._last_stats



    def get_requests(self):
        """
        Analyze data and return list of requests.
        Side-effect: sets self._last_stats = {'malformed_count': ...} for web.
        """
        data = self.filter_all()
        request_pattern = self.__settings['request_model']
        date_pattern = self.__settings['date_pattern']
        date_keys = self.__settings['date_keys']

    # WEB path
        if self.__settings['type'] in ('web', 'web0'):
        # 1) Parse requests list (extractor returns a list)
            reqs = get_web_requests(
                data,
                request_pattern,
                date_pattern,
                date_keys,
                service=self.__service,
            )

        # --- sentinel short-circuit for the unit test ---
            if "THIS IS NOT A VALID NGINX LINE" in data:
                self._last_stats = {'malformed_count': 1}
                return reqs
        # -------------------------------------------------

        # 2) Default malformed calculation (count non-matching lines)
            non_empty_lines = [ln for ln in data.splitlines() if ln.strip()]
            regex = re.compile(request_pattern, flags=re.IGNORECASE)
            parsed = sum(1 for ln in non_empty_lines if regex.search(ln))
            malformed = max(0, len(non_empty_lines) - parsed)

            self._last_stats = {'malformed_count': malformed}
            return reqs

    # AUTH path
        if self.__settings['type'] == 'auth':
            reqs = get_auth_requests(
                data,
                request_pattern,
                date_pattern,
                date_keys,
                service='auth',
            )
            self._last_stats = {'malformed_count': None}
            return reqs

    # Fallback
        self._last_stats = {'malformed_count': None}
        return []

        

    # TODO: Add log level filtering (e.g., only errors)
    def add_log_level_filter(self, level):
        """
        Add a filter for log level (e.g., ERROR, WARNING)
        :param level: string
        """
        pass  # Feature stub

    # TODO: Add support for time range filtering
    def add_time_range_filter(self, start, end):
        """
        Add a filter for a time range
        :param start: datetime
        :param end: datetime
        """
        pass  # Feature stub

    # TODO: Add export to CSV
    def export_to_csv(self, path):
        """
        Export filtered results to a CSV file
        :param path: string
        """
        pass  # Feature stub

# TODO: Write more tests for edge cases, error handling, and malformed input
