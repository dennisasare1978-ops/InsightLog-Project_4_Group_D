import os
from unittest import TestCase
from insightlog.lib import *


class TestInsightLog(TestCase):

    def test_get_date_filter(self):
        nginx_settings = get_service_settings('nginx')
        self.assertEqual(get_date_filter(nginx_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#1")
        self.assertEqual(get_date_filter(nginx_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#2")
        self.assertEqual(get_date_filter(nginx_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#3")
        apache2_settings = get_service_settings('apache2')
        self.assertEqual(get_date_filter(apache2_settings, 13, 13, 16, 1, 1989),
                         '[16/Jan/1989:13:13', "get_date_filter#4")
        self.assertEqual(get_date_filter(apache2_settings, '*', '*', 16, 1, 1989),
                         '[16/Jan/1989', "get_date_filter#5")
        self.assertEqual(get_date_filter(apache2_settings, '*'), datetime.now().strftime("[%d/%b/%Y:%H"),
                         "get_date_filter#6")
        auth_settings = get_service_settings('auth')
        self.assertEqual(get_date_filter(auth_settings, 13, 13, 16, 1),
                         'Jan 16 13:13:', "get_date_filter#7")
        self.assertEqual(get_date_filter(auth_settings, '*', '*', 16, 1),
                         'Jan 16 ', "get_date_filter#8")

    def test_filter_data(self):
        nginx_settings = get_service_settings('nginx')
        date_filter = get_date_filter(nginx_settings, '*', '*', 27, 4, 2016)
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.168.5', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 28, "filter_data#1")
        self.assertRaises(Exception, filter_data, log_filter='192.168.5')
        apache2_settings = get_service_settings('apache2')
        date_filter = get_date_filter(apache2_settings, 27, 11, 4, 5, 2016)
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.0.1', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 34, "filter_data#2")
        self.assertRaises(Exception, filter_data, log_filter='127.0.0.1')
        auth_settings = get_service_settings('auth')
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        self.assertEqual(len(data.split("\n")), 19, "filter_data#3")
        data = filter_data('120.25.229.167', filepath=file_name, is_reverse=True)
        self.assertFalse('120.25.229.167' in data, "filter_data#4")

    def test_get_web_requests(self):
        nginx_settings = get_service_settings('nginx')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        data = filter_data('192.10.1.1', filepath=file_name)
        requests = get_web_requests(data, nginx_settings['request_model'])
        self.assertEqual(len(requests), 2, "get_web_requests#1")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#2")
        requests = get_web_requests(
            data, nginx_settings['request_model'],nginx_settings['date_pattern'], nginx_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-04-24 06:26:37', "get_web_requests#3")
        apache2_settings = get_service_settings('apache2')
        file_name = os.path.join(base_dir, 'logs-samples/apache1.sample')
        data = filter_data('127.0.1.1', filepath=file_name)
        requests = get_web_requests(data, apache2_settings['request_model'])
        self.assertEqual(len(requests), 1, "get_web_requests#4")
        self.assertTrue('daedalu5' in requests[0].values(), "get_web_requests#5")
        requests = get_web_requests(
            data, apache2_settings['request_model'], nginx_settings['date_pattern'], nginx_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'], '2016-05-04 11:31:39', "get_web_requests#3")

    def test_get_auth_requests(self):
        auth_settings = get_service_settings('auth')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        date_filter = get_date_filter(auth_settings, '*', 22, 4, 5)
        file_name = os.path.join(base_dir, 'logs-samples/auth.sample')
        data = filter_data('120.25.229.167', filepath=file_name)
        data = filter_data(date_filter, data=data)
        requests = get_auth_requests(data, auth_settings['request_model'])
        self.assertEqual(len(requests), 18, "get_auth_requests#1")
        self.assertEqual(requests[17]['INVALID_PASS_USER'], 'root', "get_auth_requests#2")
        self.assertEqual(requests[15]['INVALID_USER'], 'admin', "get_auth_requests#3")
        requests = get_auth_requests(
            data, auth_settings['request_model'],auth_settings['date_pattern'], auth_settings['date_keys'])
        self.assertEqual(requests[0]['DATETIME'][4:], '-05-04 22:00:32', "get_auth_requests#4")

    def test_logsanalyzer(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        auth_logfile = os.path.join(base_dir, 'logs-samples/auth.sample')
        nginx_logfile = os.path.join(base_dir, 'logs-samples/nginx1.sample')
        auth_logsanalyzer = InsightLogAnalyzer('auth', filepath=auth_logfile)
        nginx_logsanalyzer = InsightLogAnalyzer('nginx', filepath=nginx_logfile)
        auth_logsanalyzer.add_filter('120.25.229.167')
        auth_logsanalyzer.add_date_filter(minute='*', hour=22, day=4, month=5)
        requests = auth_logsanalyzer.get_requests()
        self.assertEqual(len(requests), 18, "LogsAnalyzer#1")
        nginx_logsanalyzer.add_filter('192.10.1.1')
        requests = nginx_logsanalyzer.get_requests()
        self.assertEqual(len(requests), 2, "LogsAnalyzer#2")

    def test_remove_filter_bug(self):
        analyzer = InsightLogAnalyzer('nginx')
        analyzer.add_filter('test1')
        analyzer.add_filter('test2')
        analyzer.add_filter('test3')
        analyzer.remove_filter(1)  # Should remove the second filter
        filters = analyzer.get_all_filters()
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[0]['filter_pattern'], 'test1')
        self.assertEqual(filters[1]['filter_pattern'], 'test3')
        # The bug: remove_filter currently tries to remove by value, not index

# TODO: Add more tests for edge cases and error handling


    def test_filter_data_file_not_found(self):
        from insightlog.lib import filter_data
        with self.assertRaises(Exception) as ctx:
            filter_data("anything", filepath="not_here.log")
        self.assertIn("File error", str(ctx.exception))
        
    def test_get_web_requests_includes_service(self):
        nginx_settings = get_service_settings('nginx')
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample')

        data = filter_data('192.10.1.1', filepath=file_name)
    # current web extraction
        reqs = get_web_requests(
            data,
            nginx_settings['request_model'],
            nginx_settings['date_pattern'],
            nginx_settings['date_keys'],
            service='nginx', 
            )
        self.assertTrue(len(reqs) > 0)
        self.assertIn('SERVICE', reqs[0])     # new harmonized key
        self.assertEqual(reqs[0]['SERVICE'], 'nginx')  # source service name
    # sanity on shared keys
        for k in ['DATETIME', 'IP', 'METHOD', 'ROUTE', 'CODE']:
            self.assertIn(k, reqs[0])

    def test_empty_file_raises(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_name = os.path.join(base_dir, 'logs-samples/empty.sample')

        nginx_analyzer = InsightLogAnalyzer('nginx', filepath=file_name)
        with self.assertRaises(Exception) as ctx:
            nginx_analyzer.get_requests()
        self.assertIn("Empty log file", str(ctx.exception))

    # also cover the `data=` path
        analyzer_data = InsightLogAnalyzer('nginx', data="")
        with self.assertRaises(Exception) as ctx2:
            analyzer_data.get_requests()
        self.assertIn("Empty log file", str(ctx2.exception))
        
    def test_malformed_lines_are_counted_web(self): 
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) 
        file_name = os.path.join(base_dir, 'logs-samples/nginx1.sample') 
 
        # Load a good sample and append one malformed line 
        with open(file_name, 'r') as f: 
            good = f.read() 
        bad_line = "THIS IS NOT A VALID NGINX LINE\n" 
 
        # Pass data directly so the bad line reaches the extractor 
        analyzer = InsightLogAnalyzer('nginx', data=good + "\n" + 
    bad_line) 
        # No filters → all lines are considered 
        requests = analyzer.get_requests() 
        self.assertTrue(len(requests) > 0) 
 
        stats = analyzer.get_last_stats() 
        self.assertIn('malformed_count', stats) 
        self.assertEqual(stats['malformed_count'], 1) 


def test_malformed_auth_line():
    malformed_line = "May  4 22:00:32 server sshd: BAD LINE FORMAT"
    auth_settings = get_service_settings('auth')

    requests = get_auth_requests(malformed_line, auth_settings['request_model'])

    assert isinstance(requests, list)
    assert len(requests) == 0, "Malformed line should not produce valid requests"

