from sqlalchemy.orm import configure_mappers


# ==============================================================================


# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines
from . import objects


# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()
