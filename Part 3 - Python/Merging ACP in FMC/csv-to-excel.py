import csv
import xlsxwriter
file=open("accessrule-full-detail-production.csv")
csvread=csv.reader(file)
workbook = xlsxwriter.Workbook('production-full-detail.xlsx')  # create/read the file
worksheet = workbook.add_worksheet()   # adding a worksheet
i=1
for item in csvread:
    print(item[4])
    worksheet.write(i,1,item[0])
    worksheet.write(i,2,item[1])
    worksheet.write(i,3,item[2])
    worksheet.write(i,4,item[3])
    worksheet.write(i,5,item[4])
    worksheet.write(i,6,item[5])
    worksheet.write(i,7,item[6])
    i+=1
workbook.close()