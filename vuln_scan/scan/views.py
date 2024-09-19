from django.shortcuts import render
from django.http import JsonResponse
from .forms import URLForm
from .logic import scan_url
import logging

logger = logging.getLogger(__name__)

def scan(request):
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            try:
                results = scan_url(url)
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse(results)
                else:
                    return render(request, 'scan/scan.html', {'form': form, 'results': results})
            except Exception as e:
                logger.error(f"Error scanning URL: {e}", exc_info=True)
                error_message = str(e)
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'error': error_message}, status=500)
                else:
                    return render(request, 'error.html', {'error_message': error_message})
        else:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Invalid URL format'}, status=400)
            else:
                return render(request, 'scan/scan.html', {'form': form, 'error_message': 'Invalid URL format'})
    else:
        form = URLForm()
    
    return render(request, 'scan/scan.html', {'form': form, 'results': None})
