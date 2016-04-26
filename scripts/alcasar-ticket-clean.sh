#!/bin/bash

# alcasar-ticket-clean.sh
# by Franck BOUIJOUX & Rexy
# This script is distributed under the Gnu General Public License (GPL)

# nettoyage des fichiers de mots de passe générés après l'import d'une liste de noms.
# nettoyage des ticket PDF généré lors de la création d'usager
# delete password files generated during the importation of a list of names
# delete PDF ticket generated when creating new account

find /tmp -name '*.pwd' -exec rm -f {} \;
find /var/www/html/acc/manager/htdocs -name '*.pdf' -exec rm -f {} \;
exit 0
