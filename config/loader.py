# deep merges user config with default
# gives preference to user config
def load_config(user_path=None):
    defaults = yaml.safe_load(_DEFAULT_PATH.read_text()) or {}
    if user_path and Path(user_path).exists():
        user = yaml.safe_load(Path(user_path).read_text()) or {}
        return _deep_merge(defaults, user)
    return defaults
