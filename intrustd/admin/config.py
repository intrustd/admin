import os
import yaml

class Section(object):
    def __init__(self, nm, parent=None):
        self.name = nm
        self.parent = parent
        self.attrs = {}
        self.sections = {}

    def _get_subsection(self, nm):
        return self.sections.get(nm)

    def _add_subsection(self, s):
        self.sections[s.name] = s

    def update_attrs(self, attrs):
        self.attrs.update(attrs)

    def _validate(self, c):
        for s in self.sections.values():
            c = self.config.get(s.name, {})
            if not isinstance(c, dict):
                raise TypeError("Section is not dict")
            s._validate(c)

        for nm, a in self.attrs.items():
            a.validate(c, nm)

    def get_attribute(self, nm, c):
        if nm not in self.attrs:
            raise KeyError(nm)

        self.attrs[nm].get_from(c, nm)

class Config(object):
    def __init__(self, path=None):
        if path is None:
            if 'INTRUSTD_APPLIANCE_DIR' in os.environ:
                self.path = os.path.join(os.environ['INTRUSTD_APPLIANCE_DIR'], 'config.yaml')
            else:
                raise TypeError("expected 'path' argument or 'INTRUSTD_APPLIANCE_DIR' environment variable")

        self.sections = {}

    def open(self):
        try:
            with open(path, "rt") as f:
                self.config = yaml.load(f)
        except FileNotFoundError:
            self.config = {}

        self._validate()

    def _validate(self):
        for s in self.sections.values():
            c = self.config.get(s.name, {})
            if not isinstance(c, dict):
                raise TypeError("Section is not dict")
            s._validate(c)

    def _split_key(self, key):
        return key.split('.')

    def _is_internal_identifier(self, key):
        return key.startswith('_')

    def __getitem__(self, key):
        if not hasattr(self, 'config'):
            raise TypeError("Config not open()ed")

        key = self._split_key(key)
        section = key[:-1]

        cur = self.config
        cur_section = self
        p = []
        for s in section:
            p.append(s)
            s = cur_section._get_subsection(s)
            if s is None:
                raise KeyError('.'.join(p))

            cur = cur.get(s.name, {})

        return cur_section.get_attribute(key, cur)

    def _make_section(self, nms):
        cur = self
        for nm in nms:
            cur = self._get_subsection(nm)
            if cur is None:
                self._add_subsection(Section(nm, parent=cur))
                cur = self._get_subsection(nm)
        return cur

    def _get_subsection(self, nm):
        return self.sections.get(nm)

    def _add_subsection(self, s):
        self.sections[s.name] = s

    def section(self, nm):
        nm = self._split_key(nm)

        def mksection(cls):
            section = self._make_section(nm)
            attrs = [k for k in dir(cls) if not self._is_internal_identifier(k)]
            section.update_attrs(dict((attr, getattr(cls, attr)) for attr in attrs))

        return mksection
