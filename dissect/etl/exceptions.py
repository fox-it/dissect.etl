class Error(Exception):
    pass


class InvalidBufferError(Error):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidMarkerError(Error):
    pass


class InvalidRecordError(Error):
    pass


class ManifestNotFoundError(Error):
    pass


class ExtendedDataItemException(Error):
    pass


class InvalidHookIdException(Error):
    pass
