#!/bin/bash
echo "####################################################################################"
echo "Hi!"
echo "Ce script vous permettra d'installer wazuh-manager, elasticsearch, filebeat & kibana"
echo "By Fethi AMIROUCHE"
echo "####################################################################################"
read input

echo "#####################################################################"
echo "Installation package nécessaires à l'installation de Wazuh (Entrée) :"
echo "#####################################################################"
read input

apt install curl apt-transport-https unzip wget libcap2-bin software-properties-common lsb-release gnupg

echo "#####################################"
echo "Installation de la clé GPG (Entrée) :"
echo "#####################################"
read input

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -

echo "######################################"
echo "Ajout du dépôt de référence (Entrée) :"
echo "######################################"
read input

echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

echo "####################################################"
echo "Mettre à jour les informations du package (Entrée) :"
echo "####################################################"
read input

apt-get update

echo "########################################################"
echo "Installation du package du gestionnaire Wazuh (Entrée) :"
echo "########################################################"
read input

apt-get install wazuh-manager -y

echo "###################################################################"
echo "Activation et démarrage du service de gestionnaire Wazuh (Entrée) :"
echo "###################################################################"
read input

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

echo "###################################################"
echo " Vérification du statut de wazuh-manager (Entrée) :"
echo "###################################################"
read input

systemctl status wazuh-manager


echo "#####################################"
echo "Installation Elasticsearch (Entrée) :"
echo "#####################################"
read input

apt install elasticsearch-oss opendistroforelasticsearch


echo "#####################################################################"
echo "Téléchargement du fichier de configuration d'elasticsearch (Entrée) :"
echo "#####################################################################"
read input

curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml


echo "########################################################"
echo "Ajout des utilisateurs et rôles elasticsearch (Entrée) :"
echo "########################################################"
read input

curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/roles.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/roles_mapping.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://packages.wazuh.com/resources/4.2/open-distro/elasticsearch/roles/internal_users.yml



echo "#######################################################"
echo "Suppression des certificats de démonstration (Entrée) :"
echo "#######################################################"
read input

rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f


echo "###############################################"
echo "Téléchargement des certificats wazuh (Entrée) :"
echo "###############################################"
read input

curl -so ~/wazuh-cert-tool.sh https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -so ~/instances.yml https://packages.wazuh.com/resources/4.2/open-distro/tools/certificate-utility/instances_aio.yml


echo "########################################################"
echo "Exécution de wazuh pour créer les certificats (Entrée) :"
echo "########################################################"
read input


bash ~/wazuh-cert-tool.sh


echo "#########################################################################################"
echo "Déplacement les certificats d'Elasticsearh vers leur emplacement correspondant (Entrée) :"
echo "#########################################################################################"
read input


mkdir /etc/elasticsearch/certs/
mv ~/certs/elasticsearch* /etc/elasticsearch/certs/
mv ~/certs/admin* /etc/elasticsearch/certs/
cp ~/certs/root-ca* /etc/elasticsearch/certs/


echo "###########################################################"
echo "Activation et démarrage du service Elasticsearch (Entrée) :"
echo "###########################################################"
read input

systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

echo "##################################################"
echo "Vérification du statut de Elasticsearch (Entrée) :"
echo "##################################################"
read input

systemctl status elasticsearch

echo "##################################################################################################"
echo "Exécution du script Elasticsearch securityadmin pour charger les nouvelles informations (Entrée) :"
echo "##################################################################################################"
read input

export JAVA_HOME=/usr/share/elasticsearch/jdk/ && /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem


echo "################################"
echo "Installation Filebeat (Entrée) :"
echo "################################"
read input

apt-get install filebeat

echo "################################################################################"
echo "Téléchargement du fichier de configuration Filebeat pour transmettre les alertes"
echo "Wazuh à Elasticsearch (Entrée) :"
echo "################################################################################"
read input

curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/resources/4.2/open-distro/filebeat/7.x/filebeat_all_in_one.yml


echo "###################################################################"
echo "Téléchargement du modèles des alertes pour Elasticsearch (Entrée) :"
echo "###################################################################"
read input

curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json


echo "#######################################################"
echo "Téléchargement du module Wazuh pour Filebeat (Entrée) :"
echo "#######################################################"
read input

curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module


echo "##############################################"
echo "Copie des certificats Elasticsearch (Entrée) :"
echo "##############################################"
read input

mkdir /etc/filebeat/certs
cp ~/certs/root-ca.pem /etc/filebeat/certs/
mv ~/certs/filebeat* /etc/filebeat/certs/

echo "######################################################"
echo "Activation et démarrage du service Filebeat (Entrée) :"
echo "######################################################"
read input

systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat

echo "#############################################"
echo "Vérification du status de filebeat (Entrée) :"
echo "#############################################"
read input

systemctl status filebeat


echo "#################################"
echo "Installation de kibana (Entrée) :"
echo "#################################"
read input

apt-get install opendistroforelasticsearch-kibana -y


curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/resources/4.2/open-distro/kibana/7.x/kibana_all_in_one.yml


mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana/data

echo "#######################################################################"
echo "Définir le shell utilisateur kibana à /bin/bash et su kibana (Entrée) :"
echo "#######################################################################"
read input

sed -i 31c'kibana:x:110:114::/home/kibana:/bin/bash' /etc/passwd
su -l user -c cd /usr/share/kibana

echo "########################################"
echo "Installation du plugin kibana (Entrée) :"
echo "########################################"
read input

cd /usr/share/kibana
/usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.2.5_7.10.2-1.zip --allow-root


echo "###############################################"
echo "Copier les certificats Elasticsearch (Entrée) :"
echo "###############################################"
read input


mkdir /etc/kibana/certs
cp ~/certs/root-ca.pem /etc/kibana/certs/
mv ~/certs/kibana* /etc/kibana/certs/
chown kibana:kibana /etc/kibana/certs/*


echo "################################################"
echo "Reliez le socket Kibana au port 443 : (Entrée) :"
echo "################################################"
read input


/sbin/setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node


echo "####################################################"
echo "Activation et démarrage du service kibana (Entrée) :"
echo "####################################################"
read input

systemctl daemon-reload
systemctl enable kibana
systemctl start kibana

echo "###########################################"
echo "Vérification du status de kibana (Entrée) :"
echo "###########################################"
read input

systemctl status kibana

echo "###########################"
echo "Accédez à l'interface Web :"
echo "###########################"

echo "URL: https://<wazuh_server_ip> user: admin password: admin"

echo "Bye !"