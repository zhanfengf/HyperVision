rm ../temp/*
group=$1
item=$2
echo group $group item $dataset
cd ..
rm data/*
echo $(date +"%Y-%m-%d %H:%M:%S") tar -xzf hypervision-dataset.tar.gz data/$item.{data,label}
tar -xzf hypervision-dataset.tar.gz data/$item.{data,label}
cd build

echo $(date +"%Y-%m-%d %H:%M:%S") ./HyperVision -config ../configuration/$group/${item}.json
./HyperVision -config ../configuration/$group/${item}.json > ../cache/${item}.log
