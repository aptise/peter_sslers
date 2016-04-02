# https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769

LIMITS = {'names/certificate': {'limit': 100, },
          'certificates/domain': {'limit': 20,
                                  'timeframe': '1 week',
                                  },
          'certificates/fqdn': {'limit': 5,
                                'timeframe': '1 week',
                                },
          'registrations/ip_address': {'limit': 500,
                                       'timeframe': '3 hours',
                                       },
          'pending_authorizations/account': {'limit': 300,
                                             'timeframe': '1 week',
                                             },
          }
