<template>
    <div class="row">

      <table id="outS11">
        <thead>
          <tr>
            <th>Domain</th>
            <th>IP</th>
            <th>ISP</th>
            <th>Record Type</th>
            <th>Host name</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in outS11" :key="row.IP">
            <td>{{row["Domain"]}}</td>
            <td>{{row["IP"]}}</td>
            <td>{{row["ISP"]}}</td>
            <td>{{row["Record Type"]}}</td>
            <td>{{row["hostname"]}}</td>
          </tr>
        </tbody>
      </table>

      <div class="text-left">
        <br>
        <br>
        <input 
          type="entityName" 
          name="entityName" 
          v-model="entityName"
          placeholder="Entity Name"/>
        <br>
        <br>
        <input 
          type="searchDomain" 
          name="searchDomain" 
          v-model="searchDomain"
          placeholder="Search domain"/>
        <br>
        <br>
        <input 
          type="keyword" 
          name="keyword" 
          v-model="keyword"
          placeholder="Keyword"/>
        <br>
        <br>
        <button
          type="info"
          round
          @click="getOutS11">
          Search
        </button>
        <br>
        <br>
        <p class="text-danger">
            {{loadingStatus}}
        </p>
        <p class="text-primary">
            {{outS11}}
        </p>
      </div>
    </div>
</template>
<script>
import AuthenticationService from '@/services/AuthenticationService'
import getOutput from '@/services/getOutput'
import { PaperTable } from "@/components";
const tableColumns = ["Id", "Name", "Salary", "Country", "City"];
const tableData = [
  {
    id: 1,
    name: "Dakota Rice",
    salary: "$36.738",
    country: "Niger",
    city: "Oud-Turnhout"
  },
  {
    id: 2,
    name: "Minerva Hooper",
    salary: "$23,789",
    country: "Curaçao",
    city: "Sinaai-Waas"
  },
  {
    id: 3,
    name: "Sage Rodriguez",
    salary: "$56,142",
    country: "Netherlands",
    city: "Baileux"
  },
  {
    id: 4,
    name: "Philip Chaney",
    salary: "$38,735",
    country: "Korea, South",
    city: "Overland Park"
  },
  {
    id: 5,
    name: "Doris Greene",
    salary: "$63,542",
    country: "Malawi",
    city: "Feldkirchen in Kärnten"
  }
];
export default {
  components: {
    PaperTable
  },
  data() {
    return {
      outS11: [
        {"Domain": 123, "IP":'ip', "ISP":'123', "Record_Type":'123', "hostname":'123'},
        {"Domain": 123, "IP":'ip', "ISP":'123', "Record_Type":'123', "hostname":'123'}
      ],
      outS11Columns: ['Domain', 'IP', 'ISP', 'Record Type', 'hostname'],
      table1: {
        title: "Stripped Table",
        subTitle: "Here is a subtitle for this table",
        columns: [...tableColumns],
        data: [...tableData]
      },
      table2: {
        title: "Table on Plain Background",
        subTitle: "Here is a subtitle for this table",
        columns: [...tableColumns],
        data: [...tableData]
      },
      tableOutS11:{
        title: "OutS11 table data",
        subTitle:"Subdomains of the domain ",
        columns: this.outS11Columns,
        data: this.outS11
      },
      email: '',
      password: '',
      entityName: '',
      searchDomain: '',
      keyword:'',
      loadingStatus: 'Please click search to start searching DFI data'
    };
  },
  methods:{
    async register(){
      const response = await AuthenticationService.register({
        email: this.email,
        password: this.password
      })
      console.log(response.data)
    },
    async getOutS11(){
      this.loadingStatus = "Working on output 11..."
      const response = await getOutput.getOutS11({
        entityName: this.entityName,
        searchDomain: this.searchDomain,
        keyword: this.keyword
      })
      this.outS11 = response.data['outS11']
      this.outS11Columns = Object.keys(outS11[0])
    }
  }
};
</script>
<style>
table {
  font-family: 'Open Sans', sans-serif;
  width: 750px;
  border-collapse: collapse;
  border: 3px solid #44475C;
  margin: 10px 10px 0 10px;
}

table th {
  text-transform: uppercase;
  text-align: left;
  background: #44475C;
  color: #FFF;
  padding: 8px;
  min-width: 30px;
}

table td {
  text-align: left;
  padding: 8px;
  border-right: 2px solid #7D82A8;
}
table td:last-child {
  border-right: none;
}
table tbody tr:nth-child(2n) td {
  background: #D4D8F9;
}
</style>
