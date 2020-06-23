<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class BuyController extends Controller
{
    public function makebuy()
    {
        $requestPTP = new RequestController();
        $requestPTP->doRequestPtp();
    }

}
