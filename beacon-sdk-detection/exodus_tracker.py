import requests
import io
import logging
import json
import os
import re
from collections import namedtuple
import glob
import subprocess
import itertools

import utils
import config

logger = logging.getLogger(__name__)

EXODUS_URL = 'https://reports.exodus-privacy.eu.org'


def update_local_db(db_name, url, local_file):
    """Update Local DBs."""
    update = None
    inmemoryfile = None
    try:
        response = requests.get(url, timeout=3)
        resp = response.content
        inmemoryfile = io.BytesIO(resp)
        # Create on first run
        if not utils.is_file_exists(local_file):
            return resp
        # Check1: SHA256 Change
        if utils.sha256_object(inmemoryfile) != utils.sha256(local_file):
            # Hash Changed
            logger.info('%s Database is outdated!', db_name)
            update = resp
        else:
            logger.info('%s Database is up-to-date', db_name)
        return update
    except Exception:
        logger.exception('[ERROR] %s DB Update', db_name)
        return update
    finally:
        if inmemoryfile:
            inmemoryfile.truncate(0)



class Trackers:
    def __init__(self, apk_dir):
        self.apk = None
        self.apk_dir = apk_dir
        self.tracker_db = os.path.join(
            os.getcwd(),
            'exodus_trackers')
        self.signatures = None
        self.nb_trackers_signature = 0
        self.compiled_tracker_signature = None
        self.classes = None
        # self._update_tracker_db()

    def _update_tracker_db(self):
        """Update Trackers DB."""
        try:

            exodus_db = '{}/api/trackers'.format(EXODUS_URL)
            resp = update_local_db('Trackers',
                                   exodus_db,
                                   self.tracker_db)
            # Check1: SHA256 Change
            if resp:
                # DB needs update
                # Check2: DB Syntax Changed
                data = json.loads(resp.decode('utf-8', 'ignore'))
                is_db_format_good = False
                if 'trackers' in data:
                    if '1' in data['trackers']:
                        if 'code_signature' in data['trackers']['1']:
                            is_db_format_good = True
                if is_db_format_good:
                    # DB Format is not changed. Let's update DB
                    logger.info('Updating Trackers Database....')
                    with open(self.tracker_db, 'wb') as wfp:
                        wfp.write(resp)
                else:
                    logger.info('Trackers Database format from '
                                'reports.exodus-privacy.eu.org has changed.'
                                ' Database is not updated. '
                                )
        except Exception:
            logger.exception('[ERROR] Trackers DB Update')

    def _compile_signatures(self):
        """
        Compile Signatures.
        Compiles the regex associated to each signature, in order to speed up
        the trackers detection.
        :return: A compiled list of signatures.
        """
        self.compiled_tracker_signature = []
        try:
            self.compiled_tracker_signature = [re.compile(track.code_signature)
                                               for track in self.signatures]
        except TypeError:
            logger.exception('compiling tracker signature failed')

    def load_trackers_signatures(self):
        """
        Load trackers signatures from the official Exodus database.
        :return: a dictionary of signatures.
        """
        self.signatures = []
        with io.open(self.tracker_db,
                     mode='r',
                     encoding='utf8',
                     errors='ignore') as flip:
            data = json.loads(flip.read())
        for elm in data['trackers']:
            self.signatures.append(
                namedtuple('tracker',
                           data['trackers'][elm].keys())(
                               *data['trackers'][elm].values()))
        self._compile_signatures()
        self.nb_trackers_signature = len(self.signatures)

    def get_embedded_classes(self):
        """
        Get the list of Java classes from all DEX files.
        :return: list of Java classes
        """
        if self.classes is not None:
            return self.classes
        for dex_file in glob.iglob(os.path.join(self.apk_dir, '*.dex')):
            bs_path = config.BAKSMALI_BINARY
            args = [utils.find_java_binary(), '-jar',
                    bs_path, 'list', 'classes', dex_file]
            classes = subprocess.check_output(
                args, universal_newlines=True).splitlines()
            if self.classes is not None:
                self.classes = self.classes + classes
            else:
                self.classes = classes
        return self.classes

    def detect_trackers_in_list(self, class_list):
        """
        Detect embedded trackers in the provided classes list.
        :return: list of embedded trackers
        """
        if self.signatures is None:
            self.load_trackers_signatures()

        def _detect_tracker(sig, tracker, class_list):
            for clazz in class_list:
                if sig.search(clazz):
                    return tracker
            return None

        results = []
        args = [(self.compiled_tracker_signature[index], tracker, class_list)
                for (index, tracker) in enumerate(self.signatures) if
                len(tracker.code_signature) > 3]

        for res in itertools.starmap(_detect_tracker, args):
            if res:
                results.append(res)

        trackers = [t for t in results if t is not None]
        trackers = sorted(trackers, key=lambda trackers: trackers.name)
        return trackers

    def detect_trackers(self):
        """
        Detect embedded trackers.
        :return: list of embedded trackers
        """
        if self.signatures is None:
            self.load_trackers_signatures()
        eclasses = self.get_embedded_classes()
        if eclasses:
            return self.detect_trackers_in_list(eclasses)
        return []

    def get_trackers(self):
        """Get Trackers."""
        logger.info('Detecting Trackers')
        trackers = self.detect_trackers()
        tracker_dict = {'detected_trackers': len(trackers),
                        'total_trackers': self.nb_trackers_signature,
                        'trackers': []}
        for trk in trackers:
            trk_url = '{}/trackers/{}'.format(EXODUS_URL, trk.id)
            print(trk_url)
            tracker_dict['trackers'].append({trk.name: trk_url})
        return tracker_dict

