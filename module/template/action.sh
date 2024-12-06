#!/system/bin/sh

aceID="2257"

aceFiles="https://dl.listdl.com/iedsafe/Client/android/$aceID"
config2="$aceFiles/config2.xml"
cfg2=$(curl -s $config2)


formatDate() {
    input_date="$1"
    cleaned_date=$(echo "$input_date" | sed 's/^[A-Za-z]*, //; s/ GMT//')
    day=$(echo "$cleaned_date" | awk '{print $1}')
    month=$(echo "$cleaned_date" | awk '{print $2}')
    year=$(echo "$cleaned_date" | awk '{print $3}')
    time=$(echo "$cleaned_date" | awk '{print $4}')
    weekday=$(echo "$input_date" | awk '{print $1}' | sed 's/,$//')
    printf "%s %s %2s %s CET %s" "$weekday" "$month" "$day" "$time" "$year"
}

getLastModified() {
    local lm=$(curl -sI "$1" | grep -i "last-modified" | cut -d' ' -f2-)
    if [ -n "$lm" ]; then
        echo "$lm"
    else
        echo "[Unknown]"
        return 1
    fi
}

lmd=$(getLastModified "$config2")
if [ $? -eq 0 ]; then
	cfg2stmp=$(/system/bin/date -d "$(formatDate "$lmd")" +%s)
    echo "✅    config2.xml:  $lmd"
else
    echo "❌    config2.xml:  $lmd"
    exit 1;
fi

file=""
echo "$cfg2" | while IFS= read -r line; do
    if echo "$line" | grep -q 'name="'; then
        name=$(echo "$line" | sed -n 's/.*name="\([^"]*\)".*/\1/p')
    fi
    if echo "$line" | grep -q '<A hash="'; then
        hash=$(echo "$line" | sed -n 's/.*hash="\([^"]*\)".*/\1/p')
        lmd=$(getLastModified "$aceFiles/$hash/$name")
        if [ $? -eq 0 ]; then
        	filestmp=$(( $(/system/bin/date -d "$(formatDate "$lmd")" +%s) + 3600 ))
			if [ "$filestmp" -gt "$cfg2stmp" ]; then
			    echo "⚠️    $name:  $lmd"
			else
				  echo "-    $name:  $lmd"
			fi
		else
		    echo "❌    $name.xml:  $lmd"
		fi
        if [ -n "$name" ] && [ -n "$hash" ]; then
            name=""
        fi
    fi
done
printf "- Completed checking!\n\n\n"

sleep 4
exit;